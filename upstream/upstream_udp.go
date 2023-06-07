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

type udpUpstream struct {
	ctx         context.Context
	tag         string
	logger      log.ContextLogger
	dialer      NetDialer
	address     netip.AddrPort
	idleTimeout time.Duration
	connPool    *connpool.ConnPool
}

var _ adapter.Upstream = (*udpUpstream)(nil)

func NewUDPUpstream(ctx context.Context, logger log.Logger, options upstream.UpstreamOption) (adapter.Upstream, error) {
	u := &udpUpstream{
		ctx:    ctx,
		tag:    options.Tag,
		logger: log.NewContextLogger(log.NewTagLogger(logger, fmt.Sprintf("upstream/%s", options.Tag))),
	}
	if options.UDPOption.Address == "" {
		return nil, fmt.Errorf("create udp upstream fail: address is empty")
	}
	ip, err := netip.ParseAddr(options.UDPOption.Address)
	if err == nil {
		options.UDPOption.Address = net.JoinHostPort(ip.String(), "53")
	}
	address, err := netip.ParseAddrPort(options.UDPOption.Address)
	if err != nil || !address.IsValid() {
		return nil, fmt.Errorf("create udp upstream fail: parse address fail: %s", err)
	}
	u.address = address
	if options.UDPOption.IdleTimeout > 0 {
		u.idleTimeout = time.Duration(options.UDPOption.IdleTimeout)
	} else {
		u.idleTimeout = constant.UDPIdleTimeout
	}
	dialer, err := newNetDialer(options.DialerOption)
	if err != nil {
		return nil, fmt.Errorf("create udp upstream fail: create dialer fail: %s", err)
	}
	u.dialer = dialer
	return u, nil
}

func (u *udpUpstream) Tag() string {
	return u.tag
}

func (u *udpUpstream) Type() string {
	return constant.UpstreamUDP
}

func (u *udpUpstream) Start() error {
	connPool := connpool.New(constant.MaxConn, u.idleTimeout, func() (net.Conn, error) {
		conn, err := u.dialer.DialContext(u.ctx, constant.NetworkUDP, u.address.String())
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

func (u *udpUpstream) Close() error {
	u.connPool.Close()
	return nil
}

func (u *udpUpstream) ContextLogger() log.ContextLogger {
	return u.logger
}

func (u *udpUpstream) Exchange(ctx context.Context, dnsMsg *dns.Msg) (*dns.Msg, error) {
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
	dnsConn := &dns.Conn{Conn: newPacketConn(conn)}
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
