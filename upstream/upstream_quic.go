package upstream

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/upstream"
	"github.com/yaotthaha/cdns/upstream/bootstrap"
	"github.com/yaotthaha/cdns/upstream/dialer"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

type quicUpstream struct {
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

	tlsConfig    *tls.Config
	quicConfig   *quic.Config
	quicConn     *quicConnection
	quicConnLock sync.Mutex
}

var _ adapter.Upstream = (*quicUpstream)(nil)

func NewQUICUpstream(ctx context.Context, rootLogger log.Logger, options upstream.UpstreamOptions) (adapter.Upstream, error) {
	u := &quicUpstream{
		ctx:    ctx,
		tag:    options.Tag,
		logger: log.NewContextLogger(log.NewTagLogger(rootLogger, fmt.Sprintf("upstream/%s", options.Tag))),
	}
	if options.Options == nil {
		return nil, fmt.Errorf("create quic upstream fail: options is empty")
	}
	quicOptions := options.Options.(*upstream.UpstreamQUICOptions)
	if quicOptions.QueryTimeout > 0 {
		u.queryTimeout = time.Duration(quicOptions.QueryTimeout)
	} else {
		u.queryTimeout = constant.DNSQueryTimeout
	}
	if quicOptions.IdleTimeout > 0 {
		u.idleTimeout = time.Duration(quicOptions.IdleTimeout)
	} else {
		u.idleTimeout = constant.UDPIdleTimeout
	}
	if quicOptions.ConnectTimeout > 0 {
		u.connectTimeout = time.Duration(quicOptions.ConnectTimeout)
	} else {
		u.connectTimeout = constant.UDPConnectTimeout
	}
	domain, ip, port, err := parseAddress(quicOptions.Address, 784)
	if err != nil {
		return nil, fmt.Errorf("create quic upstream fail: parse address fail: %s", err)
	}
	if domain != "" {
		if quicOptions.Bootstrap == nil {
			return nil, fmt.Errorf("create quic upstream fail: bootstrap is needed when address is domain")
		}
		b, err := bootstrap.NewBootstrap(*quicOptions.Bootstrap)
		if err != nil {
			return nil, fmt.Errorf("create quic upstream fail: create bootstrap fail: %s", err)
		}
		u.domain = domain
		u.bootstrap = b
	} else {
		u.ip = ip
	}
	u.port = port
	d, err := dialer.NewNetDialer(quicOptions.Dialer)
	if err != nil {
		return nil, fmt.Errorf("create quic upstream fail: create dialer fail: %s", err)
	}
	u.dialer = d
	var serverName string
	if u.domain != "" {
		serverName = u.domain
	} else {
		serverName = u.ip.String()
	}
	tlsConfig, err := parseTLSOptions(quicOptions.TLSOptions, serverName)
	if err != nil {
		return nil, fmt.Errorf("create quic upstream fail: %s", err)
	}
	tlsConfig.NextProtos = []string{"doq"}
	u.tlsConfig = tlsConfig
	u.quicConfig = &quic.Config{
		TokenStore:                     quic.NewLRUTokenStore(4, 8),
		InitialStreamReceiveWindow:     4 * 1024,
		MaxStreamReceiveWindow:         4 * 1024,
		InitialConnectionReceiveWindow: 8 * 1024,
		MaxConnectionReceiveWindow:     64 * 1024,
	}
	return u, nil
}

func (u *quicUpstream) Tag() string {
	return u.tag
}

func (u *quicUpstream) Type() string {
	return constant.UpstreamQUIC
}

func (u *quicUpstream) Start() error {
	go u.watch()
	return nil
}

func (u *quicUpstream) ContextLogger() log.ContextLogger {
	return u.logger
}

func (u *quicUpstream) createQUICConnection() (quic.Connection, net.Conn, error) {
	ctx, cancel := context.WithTimeout(u.ctx, u.connectTimeout)
	defer cancel()
	var (
		udpConn net.Conn
		err     error
	)
	if u.domain == "" {
		address := net.JoinHostPort(u.ip.String(), strconv.Itoa(int(u.port)))
		udpConn, err = u.dialer.DialContext(ctx, constant.NetworkUDP, address)
	} else {
		var addresses []string
		addresses, err = u.bootstrap.QueryAddress(ctx, u.domain, u.port)
		if err != nil {
			return nil, nil, err
		}
		udpConn, err = u.dialer.DialParallel(ctx, constant.NetworkUDP, addresses)
	}
	if err != nil {
		return nil, nil, err
	}
	u.logger.Debug("open new udp connection")
	quicConn, err := quic.DialEarly(u.ctx, newPacketConn(udpConn), udpConn.RemoteAddr(), u.tlsConfig.Clone(), u.quicConfig)
	if err != nil {
		return nil, nil, err
	}
	u.logger.Debug("open new quic connection")
	return quicConn, udpConn, nil
}

func (u *quicUpstream) watch() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			u.quicConnLock.Lock()
			if u.quicConn == nil {
				u.quicConnLock.Unlock()
				continue
			}
			if u.idleTimeout > 0 && time.Since(u.quicConn.lastActive) >= u.idleTimeout {
				u.logger.Info("close connection")
				u.quicConn.CloseWithError(0, "")
				u.quicConn = nil
			}
			u.quicConnLock.Unlock()
		case <-u.ctx.Done():
			return
		}
	}
}

func (u *quicUpstream) getQUICConnection() (quic.Connection, error) {
	u.quicConnLock.Lock()
	defer u.quicConnLock.Unlock()
	if u.quicConn != nil {
		return u.quicConn, nil
	}
	quicConn, udpConn, err := u.createQUICConnection()
	if err != nil {
		return nil, err
	}
	u.quicConn = newQUICConnection(quicConn, udpConn)
	return quicConn, nil
}

func (u *quicUpstream) Exchange(ctx context.Context, dnsMsg *dns.Msg) (*dns.Msg, error) {
	u.logger.InfoContext(ctx, fmt.Sprintf("exchange dns: %s", logDNSMsg(dnsMsg)))
	u.logger.DebugContext(ctx, "get connection")
	conn, err := u.getQUICConnection()
	if err != nil {
		err = fmt.Errorf("get quic connection fail: %s", err)
		u.logger.ErrorContext(ctx, err.Error())
		return nil, err
	}
	steam, err := conn.OpenStreamSync(ctx)
	if err != nil {
		err = fmt.Errorf("open steam fail: %s", err)
		u.logger.ErrorContext(ctx, err.Error())
		return nil, err
	}
	u.logger.DebugContext(ctx, "get connection success")
	dnsConn := &dns.Conn{Conn: newQUICConn(steam)}
	defer dnsConn.Close()
	u.logger.DebugContext(ctx, "write dns message")
	dnsConn.SetDeadline(time.Now().Add(u.queryTimeout))
	defer dnsConn.SetDeadline(time.Time{})
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

type quicSteamConn struct {
	quic.Stream
}

func newQUICConn(steam quic.Stream) *quicSteamConn {
	return &quicSteamConn{Stream: steam}
}

func (q *quicSteamConn) LocalAddr() net.Addr {
	return nil
}

func (q *quicSteamConn) RemoteAddr() net.Addr {
	return nil
}

type quicConnection struct {
	conn       quic.Connection
	udpConn    net.Conn
	lastActive time.Time
}

func newQUICConnection(conn quic.Connection, udpConn net.Conn) *quicConnection {
	return &quicConnection{
		conn:       conn,
		udpConn:    udpConn,
		lastActive: time.Now(),
	}
}

func (q *quicConnection) refresh() {
	q.lastActive = time.Now()
}

func (q *quicConnection) AcceptStream(ctx context.Context) (quic.Stream, error) {
	q.refresh()
	defer q.refresh()
	return q.conn.AcceptStream(ctx)
}

func (q *quicConnection) AcceptUniStream(ctx context.Context) (quic.ReceiveStream, error) {
	q.refresh()
	defer q.refresh()
	return q.conn.AcceptUniStream(ctx)
}

func (q *quicConnection) OpenStream() (quic.Stream, error) {
	q.refresh()
	defer q.refresh()
	return q.conn.OpenStream()
}

func (q *quicConnection) OpenStreamSync(ctx context.Context) (quic.Stream, error) {
	q.refresh()
	defer q.refresh()
	return q.conn.OpenStreamSync(ctx)
}

func (q *quicConnection) OpenUniStream() (quic.SendStream, error) {
	q.refresh()
	defer q.refresh()
	return q.conn.OpenUniStream()
}

func (q *quicConnection) OpenUniStreamSync(ctx context.Context) (quic.SendStream, error) {
	q.refresh()
	defer q.refresh()
	return q.conn.OpenUniStreamSync(ctx)
}

func (q *quicConnection) LocalAddr() net.Addr {
	q.refresh()
	defer q.refresh()
	return q.conn.LocalAddr()
}

func (q *quicConnection) RemoteAddr() net.Addr {
	q.refresh()
	defer q.refresh()
	return q.conn.RemoteAddr()
}

func (q *quicConnection) CloseWithError(aec quic.ApplicationErrorCode, str string) error {
	q.refresh()
	defer q.refresh()
	defer q.udpConn.Close()
	return q.conn.CloseWithError(aec, str)
}

func (q *quicConnection) Context() context.Context {
	q.refresh()
	defer q.refresh()
	return q.conn.Context()
}

func (q *quicConnection) ConnectionState() quic.ConnectionState {
	q.refresh()
	defer q.refresh()
	return q.conn.ConnectionState()
}

func (q *quicConnection) SendMessage(b []byte) error {
	q.refresh()
	defer q.refresh()
	return q.conn.SendMessage(b)
}

func (q *quicConnection) ReceiveMessage() ([]byte, error) {
	q.refresh()
	defer q.refresh()
	return q.conn.ReceiveMessage()
}
