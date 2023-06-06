package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/upstream"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

type quicUpstream struct {
	ctx          context.Context
	tag          string
	logger       log.ContextLogger
	dialer       NetDialer
	address      netip.AddrPort
	idleTimeout  time.Duration
	tlsConfig    *tls.Config
	quicConfig   *quic.Config
	quicConn     *quicConnection
	quicConnLock sync.Mutex
}

var _ adapter.Upstream = (*quicUpstream)(nil)

func NewQUICUpstream(ctx context.Context, logger log.Logger, options upstream.UpstreamOption) (adapter.Upstream, error) {
	u := &quicUpstream{
		ctx:    ctx,
		tag:    options.Tag,
		logger: log.NewContextLogger(log.NewTagLogger(logger, fmt.Sprintf("upstream/%s", options.Tag))),
	}
	if options.QUICOption.Address == "" {
		return nil, fmt.Errorf("create quic upstream fail: address is empty")
	}
	ip, err := netip.ParseAddr(options.QUICOption.Address)
	if err == nil {
		options.QUICOption.Address = net.JoinHostPort(ip.String(), "784")
	}
	address, err := netip.ParseAddrPort(options.QUICOption.Address)
	if err != nil || !address.IsValid() {
		return nil, fmt.Errorf("create quic upstream fail: parse address fail: %s", err)
	}
	u.address = address
	dialer, err := newNetDialer(options.DialerOption)
	if err != nil {
		return nil, fmt.Errorf("create quic upstream fail: create dialer fail: %s", err)
	}
	u.dialer = dialer
	tlsConfig := &tls.Config{
		InsecureSkipVerify: options.QUICOption.InsecureSkipVerify,
		ServerName:         options.QUICOption.ServerName,
		NextProtos:         []string{"doq"},
	}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = u.address.Addr().String()
	}
	if options.QUICOption.ClientCertFile != "" && options.QUICOption.ClientKeyFile == "" {
		return nil, fmt.Errorf("create quic upstream fail: client_key_file not found")
	} else if options.QUICOption.ClientCertFile == "" && options.QUICOption.ClientKeyFile != "" {
		return nil, fmt.Errorf("create quic upstream fail: client_cert_file not found")
	} else if options.QUICOption.ClientCertFile != "" && options.QUICOption.ClientKeyFile != "" {
		keyPair, err := tls.LoadX509KeyPair(options.QUICOption.ClientCertFile, options.QUICOption.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("create quic upstream fail: load x509 key pair fail: %s", err)
		}
		tlsConfig.Certificates = []tls.Certificate{keyPair}
	}
	if options.QUICOption.CAFile != "" {
		caContent, err := os.ReadFile(options.QUICOption.CAFile)
		if err != nil {
			return nil, fmt.Errorf("create quic upstream fail: load ca fail: %s", err)
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		if !tlsConfig.RootCAs.AppendCertsFromPEM(caContent) {
			return nil, fmt.Errorf("create quic upstream fail: append ca fail")
		}
	}
	u.tlsConfig = tlsConfig
	u.quicConfig = &quic.Config{}
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

func (u *quicUpstream) Close() error {
	return nil
}

func (u *quicUpstream) ContextLogger() log.ContextLogger {
	return u.logger
}

func (u *quicUpstream) createQUICConnection() (quic.Connection, net.Conn, error) {
	u.logger.Debug("open new connection")
	udpConn, err := u.dialer.DialContext(u.ctx, constant.NetworkUDP, u.address.String())
	if err != nil {
		return nil, nil, err
	}
	u.logger.Debug("open quic connection")
	quicConn, err := quic.DialEarly(u.ctx, newPacketConn(udpConn), udpConn.RemoteAddr(), u.tlsConfig, u.quicConfig)
	if err != nil {
		return nil, nil, err
	}
	u.logger.Debug("open new connection success")
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
