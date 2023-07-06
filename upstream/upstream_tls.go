package upstream

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/upstream"
	"github.com/yaotthaha/cdns/upstream/bootstrap"
	"github.com/yaotthaha/cdns/upstream/connpool"
	"github.com/yaotthaha/cdns/upstream/dialer"

	"github.com/miekg/dns"
)

type tlsUpstream struct {
	ctx    context.Context
	tag    string
	logger log.ContextLogger

	dialer    dialer.NetDialer
	domain    string
	ip        netip.Addr
	port      uint16
	bootstrap *bootstrap.Bootstrap

	queryTimeout   time.Duration
	idleTimeout    time.Duration
	connectTimeout time.Duration

	tlsConfig *tls.Config
	connPool  *connpool.ConnPool
}

var (
	_ adapter.Upstream = (*tlsUpstream)(nil)
	_ adapter.Starter  = (*tlsUpstream)(nil)
	_ adapter.Closer   = (*tlsUpstream)(nil)
	_ adapter.WithCore = (*tlsUpstream)(nil)
)

func NewTLSUpstream(ctx context.Context, logger log.ContextLogger, options upstream.UpstreamOptions) (adapter.Upstream, error) {
	u := &tlsUpstream{
		ctx:    ctx,
		tag:    options.Tag,
		logger: logger,
	}
	if options.Options == nil {
		return nil, fmt.Errorf("create tls upstream fail: options is empty")
	}
	tlsOptions := options.Options.(*upstream.UpstreamTLSOptions)
	if tlsOptions.QueryTimeout > 0 {
		u.queryTimeout = time.Duration(tlsOptions.QueryTimeout)
	} else {
		u.queryTimeout = constant.DNSQueryTimeout
	}
	if tlsOptions.IdleTimeout > 0 {
		u.idleTimeout = time.Duration(tlsOptions.IdleTimeout)
	} else {
		u.idleTimeout = constant.TCPIdleTimeout
	}
	if tlsOptions.ConnectTimeout > 0 {
		u.connectTimeout = time.Duration(tlsOptions.ConnectTimeout)
	} else {
		u.connectTimeout = constant.TCPConnectTimeout
	}
	domain, ip, port, err := parseAddress(tlsOptions.Address, 853)
	if err != nil {
		return nil, fmt.Errorf("create tls upstream fail: parse address fail: %s", err)
	}
	if domain != "" {
		if tlsOptions.Bootstrap == nil {
			return nil, fmt.Errorf("create tls upstream fail: bootstrap is needed when address is domain")
		}
		b, err := bootstrap.NewBootstrap(*tlsOptions.Bootstrap)
		if err != nil {
			return nil, fmt.Errorf("create tls upstream fail: create bootstrap fail: %s", err)
		}
		u.domain = domain
		u.bootstrap = b
	} else {
		u.ip = ip
	}
	u.port = port
	d, err := dialer.NewNetDialer(tlsOptions.Dialer)
	if err != nil {
		return nil, fmt.Errorf("create tls upstream fail: create dialer fail: %s", err)
	}
	u.dialer = d
	var serverName string
	if u.domain != "" {
		serverName = u.domain
	} else {
		serverName = u.ip.String()
	}
	tlsConfig, err := parseTLSOptions(tlsOptions.TLSOptions, serverName)
	if err != nil {
		return nil, fmt.Errorf("create tls upstream fail: %s", err)
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

func (u *tlsUpstream) WithCore(core adapter.Core) {
	if u.bootstrap != nil {
		u.bootstrap.WithCore(core)
	}
}

func (u *tlsUpstream) Dependencies() []string {
	if u.bootstrap != nil {
		return []string{u.bootstrap.UpstreamTag()}
	}
	return nil
}

func (u *tlsUpstream) Start() error {
	if u.bootstrap != nil {
		err := u.bootstrap.Start()
		if err != nil {
			return fmt.Errorf("start tls upstream fail: start bootstrap fail: %s", err)
		}
	}
	connPool := connpool.New(constant.MaxConn, u.idleTimeout, func() (net.Conn, error) {
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
		tlsConn := tls.Client(conn, u.tlsConfig.Clone())
		err = tlsConn.HandshakeContext(ctx)
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
	isClosed := false
	conn, err := u.connPool.Get()
	if err != nil {
		err = fmt.Errorf("get connection fail: %s", err)
		u.logger.ErrorContext(ctx, err.Error())
		return nil, err
	}
	u.logger.DebugContext(ctx, "get connection success")
	dnsConn := &dns.Conn{Conn: conn}
	defer func() {
		if !isClosed {
			err := u.connPool.Put(conn)
			if err != nil {
				u.logger.ErrorContext(ctx, fmt.Sprintf("put connection to pool fail: %s", err))
			}
		}
	}()
	u.logger.DebugContext(ctx, "write dns message")
	dnsConn.SetDeadline(time.Now().Add(u.queryTimeout))
	err = dnsConn.WriteMsg(dnsMsg)
	if err != nil {
		isClosed = true
		conn.Close()
		err = fmt.Errorf("write dns message fail: %s", err)
		u.logger.ErrorContext(ctx, err.Error())
		return nil, err
	}
	u.logger.DebugContext(ctx, "read dns message")
	respMsg, err := dnsConn.ReadMsg()
	if err != nil {
		isClosed = true
		conn.Close()
		err = fmt.Errorf("read dns message fail: %s", err)
		u.logger.ErrorContext(ctx, err.Error())
		return nil, err
	}
	u.logger.DebugContext(ctx, "read dns message success")
	dnsConn.SetDeadline(time.Time{})
	return respMsg, nil
}
