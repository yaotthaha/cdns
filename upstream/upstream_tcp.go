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

type tcpUpstream struct {
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

	connPool *connpool.ConnPool
}

var (
	_ adapter.Upstream = (*tcpUpstream)(nil)
	_ adapter.Starter  = (*tcpUpstream)(nil)
	_ adapter.Closer   = (*tcpUpstream)(nil)
	_ adapter.WithCore = (*tcpUpstream)(nil)
)

func NewTCPUpstream(ctx context.Context, rootLogger log.Logger, options upstream.UpstreamOptions) (adapter.Upstream, error) {
	u := &tcpUpstream{
		ctx:    ctx,
		tag:    options.Tag,
		logger: log.NewContextLogger(log.NewTagLogger(rootLogger, fmt.Sprintf("upstream/%s", options.Tag))),
	}
	if options.Options == nil {
		return nil, fmt.Errorf("create tcp upstream fail: options is empty")
	}
	tcpOptions := options.Options.(*upstream.UpstreamTCPOptions)
	if tcpOptions.QueryTimeout > 0 {
		u.queryTimeout = time.Duration(tcpOptions.QueryTimeout)
	} else {
		u.queryTimeout = constant.DNSQueryTimeout
	}
	if tcpOptions.IdleTimeout > 0 {
		u.idleTimeout = time.Duration(tcpOptions.IdleTimeout)
	} else {
		u.idleTimeout = constant.TCPIdleTimeout
	}
	if tcpOptions.ConnectTimeout > 0 {
		u.connectTimeout = time.Duration(tcpOptions.ConnectTimeout)
	} else {
		u.connectTimeout = constant.TCPConnectTimeout
	}
	domain, ip, port, err := parseAddress(tcpOptions.Address, 53)
	if err != nil {
		return nil, fmt.Errorf("create tcp upstream fail: parse address fail: %s", err)
	}
	if domain != "" {
		if tcpOptions.Bootstrap == nil {
			return nil, fmt.Errorf("create tcp upstream fail: bootstrap is needed when address is domain")
		}
		b, err := bootstrap.NewBootstrap(*tcpOptions.Bootstrap)
		if err != nil {
			return nil, fmt.Errorf("create tcp upstream fail: create bootstrap fail: %s", err)
		}
		u.domain = domain
		u.bootstrap = b
	} else {
		u.ip = ip
	}
	u.port = port
	d, err := dialer.NewNetDialer(tcpOptions.Dialer)
	if err != nil {
		return nil, fmt.Errorf("create tcp upstream fail: create dialer fail: %s", err)
	}
	u.dialer = d
	return u, nil
}

func (u *tcpUpstream) Tag() string {
	return u.tag
}

func (u *tcpUpstream) Type() string {
	return constant.UpstreamTCP
}

func (u *tcpUpstream) WithCore(core adapter.Core) {
	if u.bootstrap != nil {
		u.bootstrap.WithCore(core)
	}
}

func (u *tcpUpstream) Dependencies() []string {
	if u.bootstrap != nil {
		return []string{u.bootstrap.UpstreamTag()}
	}
	return nil
}

func (u *tcpUpstream) Start() error {
	if u.bootstrap != nil {
		err := u.bootstrap.Start()
		if err != nil {
			return fmt.Errorf("start tcp upstream fail: start bootstrap fail: %s", err)
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
