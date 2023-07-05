package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/upstream"
	"github.com/yaotthaha/cdns/upstream/bootstrap"
	"github.com/yaotthaha/cdns/upstream/dialer"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type httpsUpstream struct {
	ctx    context.Context
	tag    string
	logger log.ContextLogger

	dialer    dialer.NetDialer
	domain    string
	ip        netip.Addr
	port      uint16
	bootstrap *bootstrap.Bootstrap

	connectTimeout time.Duration
	queryTimeout   time.Duration

	url        *url.URL
	httpClient *http.Client
	enableH3   bool
	path       string
	header     http.Header
}

var _ adapter.Upstream = (*httpsUpstream)(nil)

func NewHTTPSUpstream(ctx context.Context, rootLogger log.Logger, options upstream.UpstreamOptions) (adapter.Upstream, error) {
	u := &httpsUpstream{
		ctx:    ctx,
		tag:    options.Tag,
		logger: log.NewContextLogger(log.NewTagLogger(rootLogger, fmt.Sprintf("upstream/%s", options.Tag))),
	}
	if options.Options == nil {
		return nil, fmt.Errorf("create https upstream fail: options is empty")
	}
	httpsOptions := options.Options.(*upstream.UpstreamHTTPSOptions)
	if httpsOptions.QueryTimeout > 0 {
		u.queryTimeout = time.Duration(httpsOptions.QueryTimeout)
	} else {
		u.queryTimeout = constant.DNSQueryTimeout
	}
	domain, ip, port, err := parseAddress(httpsOptions.Address, 443)
	if err != nil {
		return nil, fmt.Errorf("create https upstream fail: parse address fail: %s", err)
	}
	if domain != "" {
		if httpsOptions.Bootstrap == nil {
			return nil, fmt.Errorf("create https upstream fail: bootstrap is needed when address is domain")
		}
		b, err := bootstrap.NewBootstrap(*httpsOptions.Bootstrap)
		if err != nil {
			return nil, fmt.Errorf("create https upstream fail: create bootstrap fail: %s", err)
		}
		u.domain = domain
		u.bootstrap = b
	} else {
		u.ip = ip
	}
	u.port = port
	d, err := dialer.NewNetDialer(httpsOptions.Dialer)
	if err != nil {
		return nil, fmt.Errorf("create https upstream fail: create dialer fail: %s", err)
	}
	u.dialer = d
	uu := &url.URL{
		Scheme: "https",
	}
	if httpsOptions.Path != "" {
		uu.Path = httpsOptions.Path
	} else {
		uu.Path = "/dns-query"
	}
	if httpsOptions.Header != nil {
		u.header = http.Header{}
		for k, v := range httpsOptions.Header {
			u.header.Set(k, v)
		}
	}
	var serverName string
	if host := u.header.Get("Host"); host != "" {
		serverName = host
	} else if u.domain != "" {
		serverName = u.domain
	} else {
		serverName = u.ip.String()
	}
	var urlHost string
	if u.domain != "" {
		urlHost = net.JoinHostPort(u.domain, strconv.Itoa(int(u.port)))
	} else {
		urlHost = net.JoinHostPort(u.ip.String(), strconv.Itoa(int(u.port)))
	}
	uu.Host = urlHost
	u.url = uu
	tlsConfig, err := parseTLSOptions(httpsOptions.TLSOptions, serverName)
	if err != nil {
		return nil, fmt.Errorf("create https upstream fail: %s", err)
	}
	tlsConfig.NextProtos = []string{"dns"}
	u.httpClient = &http.Client{}
	if !httpsOptions.EnableH3 {
		var idleTimeout time.Duration
		if httpsOptions.IdleTimeout > 0 {
			idleTimeout = time.Duration(httpsOptions.IdleTimeout)
		} else {
			idleTimeout = constant.TCPIdleTimeout
		}
		u.httpClient.Transport = &http.Transport{
			DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				ctx, cancel := context.WithTimeout(u.ctx, u.connectTimeout)
				defer cancel()
				var (
					conn net.Conn
					err  error
				)
				if u.domain == "" {
					address := net.JoinHostPort(u.ip.String(), strconv.Itoa(int(u.port)))
					conn, err = u.dialer.DialContext(ctx, constant.NetworkTCP, address)
				} else {
					var addresses []string
					addresses, err = u.bootstrap.QueryAddress(ctx, u.domain, u.port)
					if err != nil {
						return nil, err
					}
					conn, err = u.dialer.DialParallel(ctx, constant.NetworkTCP, addresses)
				}
				if err != nil {
					return nil, err
				}
				u.logger.Debug("open new connection")
				return conn, nil
			},
			IdleConnTimeout:       idleTimeout,
			TLSClientConfig:       tlsConfig,
			MaxIdleConns:          constant.MaxConn,
			MaxIdleConnsPerHost:   constant.MaxConn,
			ExpectContinueTimeout: 30 * time.Second,
			ForceAttemptHTTP2:     true,
		}
	} else {
		if httpsOptions.Dialer.Socks5 != nil {
			return nil, fmt.Errorf("create https upstream fail: socks5 is not supported")
		}
		u.httpClient.Transport = &http3.RoundTripper{
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				ctx, cancel := context.WithTimeout(u.ctx, u.connectTimeout)
				defer cancel()
				var (
					conn net.Conn
					err  error
				)
				if u.domain == "" {
					address := net.JoinHostPort(u.ip.String(), strconv.Itoa(int(u.port)))
					conn, err = u.dialer.DialContext(ctx, constant.NetworkUDP, address)
				} else {
					var addresses []string
					addresses, err = u.bootstrap.QueryAddress(ctx, u.domain, u.port)
					if err != nil {
						return nil, err
					}
					conn, err = u.dialer.DialParallel(ctx, constant.NetworkUDP, addresses)
				}
				if err != nil {
					return nil, err
				}
				u.logger.Debug("open new connection")
				quicConn, err := quic.DialEarly(ctx, newPacketConn(conn), conn.RemoteAddr(), tlsCfg, cfg)
				if err != nil {
					return nil, err
				}
				u.logger.Debug("open new quic connection")
				return quicConn, nil
			},
			TLSClientConfig: tlsConfig,
		}
		u.enableH3 = true
	}
	return u, nil
}

func (u *httpsUpstream) Tag() string {
	return u.tag
}

func (u *httpsUpstream) Type() string {
	return constant.UpstreamHTTPS
}

func (u *httpsUpstream) WithCore(core adapter.Core) {
	if u.bootstrap != nil {
		u.bootstrap.WithCore(core)
	}
}

func (u *httpsUpstream) ContextLogger() log.ContextLogger {
	return u.logger
}

func (u *httpsUpstream) Exchange(ctx context.Context, dnsMsg *dns.Msg) (*dns.Msg, error) {
	u.logger.InfoContext(ctx, fmt.Sprintf("exchange dns: %s", logDNSMsg(dnsMsg)))
	u.logger.DebugContext(ctx, fmt.Sprintf("pack dns message"))
	rawDNSMsg, err := dnsMsg.Pack()
	if err != nil {
		err = fmt.Errorf("pack dns message fail: %s", err)
		u.logger.ErrorContext(ctx, err)
		return nil, err
	}
	u.logger.DebugContext(ctx, fmt.Sprintf("create http request, use http3: %t", u.enableH3))
	req, err := http.NewRequest(http.MethodPost, u.url.String(), bytes.NewBuffer(rawDNSMsg))
	if err != nil {
		err = fmt.Errorf("create http request fail: %s", err)
		u.logger.ErrorContext(ctx, err)
		return nil, err
	}
	if u.header != nil {
		req.Header = u.header.Clone()
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, u.queryTimeout)
	defer timeoutCancel()
	req = req.WithContext(timeoutCtx)
	u.logger.DebugContext(ctx, fmt.Sprintf("send http request"))
	resp, err := u.httpClient.Do(req)
	if err != nil {
		err = fmt.Errorf("send http request fail: %s", err)
		u.logger.ErrorContext(ctx, err)
		return nil, err
	}
	u.logger.DebugContext(ctx, fmt.Sprintf("send http request success"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("http status code not ok: %d", resp.StatusCode)
		u.logger.ErrorContext(ctx, err)
		return nil, err
	}
	u.logger.DebugContext(ctx, fmt.Sprintf("read response body"))
	respRawDNSMsg, err := io.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("read response body fail: %s", err)
		u.logger.ErrorContext(ctx, err)
		return nil, err
	}
	respMsg := &dns.Msg{}
	u.logger.DebugContext(ctx, fmt.Sprintf("unpack dns message"))
	err = respMsg.Unpack(respRawDNSMsg)
	if err != nil {
		err = fmt.Errorf("unpack dns message fail: %s", err)
		u.logger.ErrorContext(ctx, err)
		return nil, err
	}
	u.logger.DebugContext(ctx, "unpack dns message success")
	return respMsg, nil
}
