package upstream

import (
	"context"
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

type udpUpstream struct {
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

	udpConnPool *connpool.ConnPool
	tcpConnPool *connpool.ConnPool
}

var (
	_ adapter.Upstream = (*udpUpstream)(nil)
	_ adapter.Starter  = (*udpUpstream)(nil)
	_ adapter.Closer   = (*udpUpstream)(nil)
	_ adapter.WithCore = (*udpUpstream)(nil)
)

func NewUDPUpstream(ctx context.Context, logger log.ContextLogger, options upstream.UpstreamOptions) (adapter.Upstream, error) {
	u := &udpUpstream{
		ctx:    ctx,
		tag:    options.Tag,
		logger: logger,
	}
	if options.UDPOptions == nil {
		return nil, fmt.Errorf("create udp upstream fail: options is empty")
	}
	udpOptions := options.UDPOptions
	if udpOptions.QueryTimeout > 0 {
		u.queryTimeout = time.Duration(udpOptions.QueryTimeout)
	} else {
		u.queryTimeout = constant.DNSQueryTimeout
	}
	if udpOptions.IdleTimeout > 0 {
		u.idleTimeout = time.Duration(udpOptions.IdleTimeout)
	} else {
		u.idleTimeout = constant.UDPIdleTimeout
	}
	if udpOptions.ConnectTimeout > 0 {
		u.connectTimeout = time.Duration(udpOptions.ConnectTimeout)
	} else {
		u.connectTimeout = constant.UDPConnectTimeout
	}
	domain, ip, port, err := parseAddress(udpOptions.Address, 53)
	if err != nil {
		return nil, fmt.Errorf("create udp upstream fail: parse address fail: %s", err)
	}
	if domain != "" {
		if udpOptions.Bootstrap == nil {
			return nil, fmt.Errorf("create udp upstream fail: bootstrap is needed when address is domain")
		}
		b, err := bootstrap.NewBootstrap(*udpOptions.Bootstrap)
		if err != nil {
			return nil, fmt.Errorf("create udp upstream fail: create bootstrap fail: %s", err)
		}
		u.domain = domain
		u.bootstrap = b
	} else {
		u.ip = ip
	}
	u.port = port
	if udpOptions.Dialer.Socks5 != nil {
		return nil, fmt.Errorf("create udp upstream fail: socks5 is not supported")
	}
	d, err := dialer.NewNetDialer(udpOptions.Dialer)
	if err != nil {
		return nil, fmt.Errorf("create udp upstream fail: create dialer fail: %s", err)
	}
	u.dialer = d
	return u, nil
}

func (u *udpUpstream) Tag() string {
	return u.tag
}

func (u *udpUpstream) Type() string {
	return constant.UpstreamUDP
}

func (u *udpUpstream) WithCore(core adapter.Core) {
	if u.bootstrap != nil {
		u.bootstrap.WithCore(core)
	}
}

func (u *udpUpstream) Dependencies() []string {
	if u.bootstrap != nil {
		return []string{u.bootstrap.UpstreamTag()}
	}
	return nil
}

func (u *udpUpstream) Start() error {
	if u.bootstrap != nil {
		err := u.bootstrap.Start()
		if err != nil {
			return fmt.Errorf("start udp upstream fail: start bootstrap fail: %s", err)
		}
	}
	udpConnPool := connpool.New(constant.MaxConn, u.idleTimeout, func() (net.Conn, error) {
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
		u.logger.Debug("open new udp connection")
		return conn, nil
	})
	udpConnPool.SetPreCloseCall(func(conn net.Conn) {
		u.logger.Debug("close udp connection")
	})
	u.udpConnPool = udpConnPool
	tcpConnPool := connpool.New(constant.MaxConn, u.idleTimeout, func() (net.Conn, error) {
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
		u.logger.Debug("open new tcp connection")
		return conn, nil
	})
	tcpConnPool.SetPreCloseCall(func(conn net.Conn) {
		u.logger.Debug("close tcp connection")
	})
	u.tcpConnPool = tcpConnPool
	return nil
}

func (u *udpUpstream) Close() error {
	u.udpConnPool.Close()
	u.tcpConnPool.Close()
	return nil
}

func (u *udpUpstream) ContextLogger() log.ContextLogger {
	return u.logger
}

func (u *udpUpstream) simpleExchange(ctx context.Context, dnsMsg *dns.Msg) (*dns.Msg, error) {
	u.logger.DebugContext(ctx, "get connection")
	isClosed := false
	conn, err := u.udpConnPool.Get()
	if err != nil {
		err = fmt.Errorf("get connection fail: %s", err)
		u.logger.ErrorContext(ctx, err.Error())
		return nil, err
	}
	u.logger.DebugContext(ctx, "get connection success")
	dnsConn := &dns.Conn{Conn: newPacketConn(conn)}
	defer func() {
		if !isClosed {
			err := u.udpConnPool.Put(conn)
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

func (u *udpUpstream) tcpFallbackExchange(ctx context.Context, dnsMsg *dns.Msg) (*dns.Msg, error) {
	u.logger.DebugContext(ctx, "tcp fallback: get tcp connection")
	isClosed := false
	conn, err := u.tcpConnPool.Get()
	if err != nil {
		err = fmt.Errorf("tcp fallback: get tcp connection fail: %s", err)
		u.logger.ErrorContext(ctx, err.Error())
		return nil, err
	}
	u.logger.DebugContext(ctx, "tcp fallback: get tcp connection success")
	dnsConn := &dns.Conn{Conn: conn}
	defer func() {
		if !isClosed {
			err := u.tcpConnPool.Put(conn)
			if err != nil {
				u.logger.ErrorContext(ctx, fmt.Sprintf("tcp fallback: put tcp connection to pool fail: %s", err))
			}
		}
	}()
	u.logger.DebugContext(ctx, "tcp fallback: write dns message")
	dnsConn.SetDeadline(time.Now().Add(u.queryTimeout))
	err = dnsConn.WriteMsg(dnsMsg)
	if err != nil {
		isClosed = true
		conn.Close()
		err = fmt.Errorf("tcp fallback: write dns message fail: %s", err)
		u.logger.ErrorContext(ctx, err.Error())
		return nil, err
	}
	u.logger.DebugContext(ctx, "tcp fallback: read dns message")
	respMsg, err := dnsConn.ReadMsg()
	if err != nil {
		isClosed = true
		conn.Close()
		err = fmt.Errorf("tcp fallback: read dns message fail: %s", err)
		u.logger.ErrorContext(ctx, err.Error())
		return nil, err
	}
	u.logger.DebugContext(ctx, "tcp fallback: read dns message success")
	dnsConn.SetDeadline(time.Time{})
	return respMsg, nil
}

func (u *udpUpstream) Exchange(ctx context.Context, dnsMsg *dns.Msg) (*dns.Msg, error) {
	u.logger.InfoContext(ctx, fmt.Sprintf("exchange dns: %s", logDNSMsg(dnsMsg)))
	respMsg, err := u.simpleExchange(ctx, dnsMsg)
	if err != nil {
		return nil, err
	}
	if respMsg.Truncated {
		return u.tcpFallbackExchange(ctx, dnsMsg)
	}
	return respMsg, nil
}
