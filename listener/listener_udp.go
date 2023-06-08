package listener

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/lib/tools"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/listener"

	"github.com/miekg/dns"
)

var _ adapter.Listener = (*udpListener)(nil)

type udpListener struct {
	tag              string
	ctx              context.Context
	core             adapter.Core
	logger           log.ContextLogger
	fatalStartCloser func(error)
	listen           netip.AddrPort
	workflow         string
	udpConn          net.PacketConn
	dnsServer        *dns.Server
}

func NewUDPListener(ctx context.Context, core adapter.Core, logger log.Logger, options listener.ListenerOptions) (adapter.Listener, error) {
	l := &udpListener{
		tag:    options.Tag,
		ctx:    ctx,
		core:   core,
		logger: log.NewContextLogger(log.NewTagLogger(logger, fmt.Sprintf("listener/%s", options.Tag))),
	}
	if options.Listen == "" {
		options.Listen = ":53"
	}
	host, port, err := net.SplitHostPort(options.Listen)
	if err != nil {
		return nil, fmt.Errorf("create udp listener fail: parse listen %s fail: %s", options.Listen, err)
	}
	if host == "" {
		host = "::"
	}
	options.Listen = net.JoinHostPort(host, port)
	listenAddr, err := netip.ParseAddrPort(options.Listen)
	if err != nil {
		return nil, fmt.Errorf("create udp listener fail: parse listen %s fail: %s", options.Listen, err)
	}
	l.listen = listenAddr
	if options.Workflow == "" {
		return nil, fmt.Errorf("create udp listener fail: workflow is empty")
	}
	l.workflow = options.Workflow
	return l, nil
}

func (l *udpListener) Tag() string {
	return l.tag
}

func (l *udpListener) Type() string {
	return constant.ListenerUDP
}

func (l *udpListener) WithFatalCloser(f func(err error)) {
	l.fatalStartCloser = f
}

func (l *udpListener) Start() error {
	w := l.core.GetWorkflow(l.workflow)
	if w == nil {
		return fmt.Errorf("start udp listener fail: workflow %s not found", l.workflow)
	}
	var err error
	l.udpConn, err = net.ListenPacket(constant.NetworkUDP, l.listen.String())
	if err != nil {
		return fmt.Errorf("start udp listener fail: listen %s fail: %s", l.listen.String(), err)
	}
	l.dnsServer = &dns.Server{
		PacketConn:   l.udpConn,
		Handler:      l,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	waitLock := sync.Mutex{}
	waitLock.Lock()
	l.dnsServer.NotifyStartedFunc = waitLock.Unlock
	go func() {
		err := l.dnsServer.ActivateAndServe()
		if err != nil {
			if tools.IsCloseOrCanceled(err) {
				return
			}
			if l.fatalStartCloser != nil {
				l.fatalStartCloser(fmt.Errorf("start udp listener fail: %s", err))
			}
			l.logger.Fatal(fmt.Sprintf("start udp listener fail: %s", err))
		}
	}()
	waitLock.Lock()
	waitLock.Unlock()
	return nil
}

func (l *udpListener) Close() error {
	err := l.dnsServer.Shutdown()
	if err != nil {
		return fmt.Errorf("close udp listener fail: shutdown udp server fail: %s", err)
	}
	err = l.udpConn.Close()
	if err != nil {
		if tools.IsCloseOrCanceled(err) {
			return nil
		}
		return fmt.Errorf("close udp listener fail: %s", err)
	}
	return nil
}

func (l *udpListener) Context() context.Context {
	return l.ctx
}

func (l *udpListener) ContextLogger() log.ContextLogger {
	return l.logger
}

func (l *udpListener) GetWorkflow() adapter.Workflow {
	return l.core.GetWorkflow(l.workflow)
}

func (l *udpListener) ServeDNS(w dns.ResponseWriter, reqMsg *dns.Msg) {
	defer w.Close()
	ctx, respMsg := handler(l, reqMsg, w.RemoteAddr())
	if respMsg == nil {
		return
	}
	respMsg.Truncate(getUDPSize(reqMsg))
	err := w.WriteMsg(respMsg)
	if err != nil {
		l.logger.ErrorContext(ctx, fmt.Sprintf("write msg fail: %s", err))
		return
	}
}

// from mosdns
func getUDPSize(m *dns.Msg) int {
	var s uint16
	if opt := m.IsEdns0(); opt != nil {
		s = opt.UDPSize()
	}
	if s < dns.MinMsgSize {
		s = dns.MinMsgSize
	}
	return int(s)
}
