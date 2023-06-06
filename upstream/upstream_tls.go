package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/upstream"
	"github.com/yaotthaha/cdns/upstream/connpool"

	"github.com/miekg/dns"
)

type tlsUpstream struct {
	ctx         context.Context
	tag         string
	logger      log.ContextLogger
	dialer      NetDialer
	address     netip.AddrPort
	idleTimeout time.Duration
	tlsConfig   *tls.Config
	connPool    *connpool.ConnPool
}

var _ adapter.Upstream = (*tlsUpstream)(nil)

func NewTLSUpstream(ctx context.Context, logger log.Logger, options upstream.UpstreamOption) (adapter.Upstream, error) {
	u := &tlsUpstream{
		ctx:    ctx,
		tag:    options.Tag,
		logger: log.NewContextLogger(log.NewTagLogger(logger, fmt.Sprintf("upstream/%s", options.Tag))),
	}
	if options.TLSOption.Address == "" {
		return nil, fmt.Errorf("create tls upstream fail: address is empty")
	}
	ip, err := netip.ParseAddr(options.TLSOption.Address)
	if err == nil {
		options.TLSOption.Address = net.JoinHostPort(ip.String(), "853")
	}
	address, err := netip.ParseAddrPort(options.TLSOption.Address)
	if err != nil || !address.IsValid() {
		return nil, fmt.Errorf("create tls upstream fail: parse address fail: %s", err)
	}
	u.address = address
	if options.TLSOption.IdleTimeout > 0 {
		u.idleTimeout = time.Duration(options.TLSOption.IdleTimeout)
	} else {
		u.idleTimeout = constant.TCPIdleTimeout
	}
	dialer, err := newNetDialer(options.DialerOption)
	if err != nil {
		return nil, fmt.Errorf("create tls upstream fail: create dialer fail: %s", err)
	}
	u.dialer = dialer
	tlsConfig := &tls.Config{
		InsecureSkipVerify: options.TLSOption.InsecureSkipVerify,
		ServerName:         options.TLSOption.ServerName,
	}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = u.address.Addr().String()
	}
	if options.TLSOption.ClientCertFile != "" && options.TLSOption.ClientKeyFile == "" {
		return nil, fmt.Errorf("create tls upstream: client_key_file not found")
	} else if options.TLSOption.ClientCertFile == "" && options.TLSOption.ClientKeyFile != "" {
		return nil, fmt.Errorf("create tls upstream: client_cert_file not found")
	} else if options.TLSOption.ClientCertFile != "" && options.TLSOption.ClientKeyFile != "" {
		keyPair, err := tls.LoadX509KeyPair(options.TLSOption.ClientCertFile, options.TLSOption.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("create tls upstream fail: load x509 key pair fail: %s", err)
		}
		tlsConfig.Certificates = []tls.Certificate{keyPair}
	}
	if options.TLSOption.CAFile != "" {
		caContent, err := os.ReadFile(options.TLSOption.CAFile)
		if err != nil {
			return nil, fmt.Errorf("create tls upstream fail: load ca fail: %s", err)
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		if !tlsConfig.RootCAs.AppendCertsFromPEM(caContent) {
			return nil, fmt.Errorf("create tls upstream fail: append ca fail")
		}
	}
	u.tlsConfig = tlsConfig
	return u, nil
}

func (u *tlsUpstream) Tag() string {
	return u.tag
}

func (u *tlsUpstream) Type() string {
	return constant.UpstreamTLS
}

func (u *tlsUpstream) Start() error {
	connPool := connpool.New(constant.MaxConn, u.idleTimeout, func() (net.Conn, error) {
		conn, err := u.dialer.DialContext(u.ctx, constant.NetworkTCP, u.address.String())
		if err != nil {
			return nil, err
		}
		u.logger.Debug("open new connection")
		tlsConn := tls.Client(conn, u.tlsConfig.Clone())
		err = tlsConn.Handshake()
		if err != nil {
			return nil, err
		}
		u.logger.Debug("tls handshake success")
		return tlsConn, nil
	})
	connPool.SetPreCloseCall(func(conn net.Conn) {
		u.logger.Debug("close connection")
	})
	u.connPool = connPool
	return nil
}

func (u *tlsUpstream) Close() error {
	u.connPool.Close()
	return nil
}

func (u *tlsUpstream) ContextLogger() log.ContextLogger {
	return u.logger
}

func (u *tlsUpstream) Exchange(ctx context.Context, dnsMsg *dns.Msg) (*dns.Msg, error) {
	u.logger.InfoContext(ctx, fmt.Sprintf("exchange dns: %s", logDNSMsg(dnsMsg)))
	u.logger.DebugContext(ctx, "get connection")
	conn, err := u.connPool.Get()
	if err != nil {
		err = fmt.Errorf("get connection fail: %s", err)
		u.logger.ErrorContext(ctx, err.Error())
		return nil, err
	}
	u.logger.DebugContext(ctx, "get connection success")
	dnsConn := &dns.Conn{Conn: conn}
	defer func() {
		err := u.connPool.Put(conn)
		if err != nil {
			u.logger.ErrorContext(ctx, fmt.Sprintf("put connection to pool fail: %s", err))
		}
	}()
	u.logger.DebugContext(ctx, "write dns message")
	if deadline, ok := ctx.Deadline(); ok {
		dnsConn.SetDeadline(deadline)
	} else {
		dnsConn.SetDeadline(time.Now().Add(30 * time.Second))
	}
	err = dnsConn.WriteMsg(dnsMsg)
	if err != nil {
		err = fmt.Errorf("write dns message fail: %s", err)
		u.logger.ErrorContext(ctx, err.Error())
		return nil, err
	}
	u.logger.DebugContext(ctx, "read dns message")
	respMsg, err := dnsConn.ReadMsg()
	if err != nil {
		err = fmt.Errorf("read dns message fail: %s", err)
		u.logger.ErrorContext(ctx, err.Error())
		return nil, err
	}
	u.logger.DebugContext(ctx, "read dns message success")
	return respMsg, nil
}
