package upstream

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/upstream"
	"github.com/yaotthaha/cdns/upstream/connpool"

	"github.com/miekg/dns"
)

type tcpUpstream struct {
	ctx         context.Context
	tag         string
	logger      log.ContextLogger
	dialer      NetDialer
	address     netip.AddrPort
	idleTimeout time.Duration
	connPool    *connpool.ConnPool
}

var _ adapter.Upstream = (*tcpUpstream)(nil)

func NewTCPUpstream(ctx context.Context, logger log.Logger, options upstream.UpstreamOption) (adapter.Upstream, error) {
	u := &tcpUpstream{
		ctx:    ctx,
		tag:    options.Tag,
		logger: log.NewContextLogger(log.NewTagLogger(logger, fmt.Sprintf("upstream/%s", options.Tag))),
	}
	if options.TCPOption.Address == "" {
		return nil, fmt.Errorf("create tcp upstream fail: address is empty")
	}
	ip, err := netip.ParseAddr(options.TCPOption.Address)
	if err == nil {
		options.TCPOption.Address = net.JoinHostPort(ip.String(), "53")
	}
	address, err := netip.ParseAddrPort(options.TCPOption.Address)
	if err != nil || !address.IsValid() {
		return nil, fmt.Errorf("create tcp upstream fail: parse address fail: %s", err)
	}
	u.address = address
	if options.TCPOption.IdleTimeout > 0 {
		u.idleTimeout = time.Duration(options.TCPOption.IdleTimeout)
	} else {
		u.idleTimeout = constant.TCPIdleTimeout
	}
	dialer, err := newNetDialer(options.DialerOption)
	if err != nil {
		return nil, fmt.Errorf("create tcp upstream fail: create dialer fail: %s", err)
	}
	u.dialer = dialer
	return u, nil
}

func (u *tcpUpstream) Tag() string {
	return u.tag
}

func (u *tcpUpstream) Type() string {
	return constant.UpstreamTCP
}

func (u *tcpUpstream) Start() error {
	connPool := connpool.New(constant.MaxConn, u.idleTimeout, func() (net.Conn, error) {
		conn, err := u.dialer.DialContext(u.ctx, constant.NetworkTCP, u.address.String())
		if err != nil {
			return nil, err
		}
		u.logger.Debug("open new connection")
		return conn, nil
	})
	connPool.SetPreCloseCall(func(conn net.Conn) {
		u.logger.Debug("close connection")
	})
	u.connPool = connPool
	return nil
}

func (u *tcpUpstream) Close() error {
	u.connPool.Close()
	return nil
}

func (u *tcpUpstream) ContextLogger() log.ContextLogger {
	return u.logger
}

func (u *tcpUpstream) Exchange(ctx context.Context, dnsMsg *dns.Msg) (*dns.Msg, error) {
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
	if deadline, ok := ctx.Deadline(); ok {
		dnsConn.SetDeadline(deadline)
	} else {
		dnsConn.SetDeadline(time.Now().Add(10 * time.Second))
	}
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
