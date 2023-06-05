package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/upstream"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type httpsUpstream struct {
	ctx        context.Context
	tag        string
	logger     log.ContextLogger
	dialer     NetDialer
	address    netip.AddrPort
	httpClient *http.Client
	useH3      bool
	url        *url.URL
	header     http.Header
}

var _ adapter.Upstream = (*httpsUpstream)(nil)

func NewHTTPSUpstream(ctx context.Context, logger log.Logger, options upstream.UpstreamOption) (adapter.Upstream, error) {
	u := &httpsUpstream{
		ctx:     ctx,
		tag:     options.Tag,
		logger:  log.NewContextLogger(log.NewTagLogger(logger, fmt.Sprintf("upstream/%s/%s", constant.UpstreamHTTPS, options.Tag))),
		address: options.HTTPSOption.Address,
	}
	dialer, err := newNetDialer(options.DialerOption)
	if err != nil {
		return nil, fmt.Errorf("create tcp upstream: %s", err)
	}
	u.dialer = dialer
	u.url = (*url.URL)(options.HTTPSOption.URL)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: options.HTTPSOption.InsecureSkipVerify,
		ServerName:         options.HTTPSOption.ServerName,
		NextProtos:         []string{"dns"},
	}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = u.url.Hostname()
	}
	if options.HTTPSOption.ClientCertFile != "" && options.HTTPSOption.ClientKeyFile == "" {
		return nil, fmt.Errorf("create https upstream: client_key_file not found")
	} else if options.HTTPSOption.ClientCertFile == "" && options.HTTPSOption.ClientKeyFile != "" {
		return nil, fmt.Errorf("create https upstream: client_cert_file not found")
	} else if options.HTTPSOption.ClientCertFile != "" && options.HTTPSOption.ClientKeyFile != "" {
		keyPair, err := tls.LoadX509KeyPair(options.HTTPSOption.ClientCertFile, options.HTTPSOption.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("create https upstream: load x509 key pair fail: %s", err)
		}
		tlsConfig.Certificates = []tls.Certificate{keyPair}
	}
	if options.HTTPSOption.CAFile != "" {
		caContent, err := os.ReadFile(options.HTTPSOption.CAFile)
		if err != nil {
			return nil, fmt.Errorf("create https upstream: load ca fail: %s", err)
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		if !tlsConfig.RootCAs.AppendCertsFromPEM(caContent) {
			return nil, fmt.Errorf("create https upstream: append ca fail")
		}
	}
	if options.HTTPSOption.Header != nil {
		u.header = http.Header{}
		for k, v := range options.HTTPSOption.Header {
			u.header.Set(k, v)
		}
	}
	u.httpClient = &http.Client{}
	if !options.HTTPSOption.UseH3 {
		var idleTimeout time.Duration
		if options.HTTPSOption.IdleTimeout > 0 {
			idleTimeout = time.Duration(options.HTTPSOption.IdleTimeout)
		} else {
			idleTimeout = constant.TCPIdleTimeout
		}
		u.httpClient.Transport = &http.Transport{
			DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				conn, err := u.dialer.DialContext(ctx, constant.NetworkTCP, u.address.String())
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
		u.httpClient.Transport = &http3.RoundTripper{
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				conn, err := u.dialer.DialContext(ctx, constant.UpstreamUDP, u.address.String())
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
		u.useH3 = true
	}
	return u, nil
}

func (u *httpsUpstream) Tag() string {
	return u.tag
}

func (u *httpsUpstream) Type() string {
	return constant.UpstreamHTTPS
}

func (u *httpsUpstream) Start() error {
	return nil
}

func (u *httpsUpstream) Close() error {
	return nil
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
	u.logger.DebugContext(ctx, fmt.Sprintf("create http request, use http3: %t", u.useH3))
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
	req = req.WithContext(ctx)
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
