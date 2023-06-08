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

type tcpListener struct {
	tag              string
	ctx              context.Context
	core             adapter.Core
	logger           log.ContextLogger
	fatalStartCloser func(error)
	listen           netip.AddrPort
	workflow         string
	tcpListener      net.Listener
	dnsServer        *dns.Server
}

func NewTCPListener(ctx context.Context, core adapter.Core, logger log.Logger, options listener.ListenerOptions) (adapter.Listener, error) {
	l := &tcpListener{
		tag:    options.Tag,
		ctx:    ctx,
		core:   core,
		logger: log.NewContextLogger(log.NewTagLogger(logger, fmt.Sprintf("listener/%s/%s", constant.ListenerTCP, options.Tag))),
	}
	if options.Listen == "" {
		options.Listen = ":53"
	}
	host, port, err := net.SplitHostPort(options.Listen)
	if err != nil {
		return nil, fmt.Errorf("create tcp listener fail: parse listen %s fail: %s", options.Listen, err)
	}
	if host == "" {
		host = "::"
	}
	options.Listen = net.JoinHostPort(host, port)
	listenAddr, err := netip.ParseAddrPort(options.Listen)
	if err != nil {
		return nil, fmt.Errorf("create tcp listener fail: parse listen %s fail: %s", options.Listen, err)
	}
	l.listen = listenAddr
	if options.Workflow == "" {
		return nil, fmt.Errorf("create tcp listener fail: workflow is empty")
	}
	l.workflow = options.Workflow
	return l, nil
}

func (l *tcpListener) Tag() string {
	return l.tag
}

func (l *tcpListener) Type() string {
	return constant.ListenerTCP
}

func (l *tcpListener) WithFatalCloser(f func(err error)) {
	l.fatalStartCloser = f
}

func (l *tcpListener) Start() error {
	w := l.core.GetWorkflow(l.workflow)
	if w == nil {
		return fmt.Errorf("start tcp listener fail: workflow %s not found", l.workflow)
	}
	var err error
	l.tcpListener, err = net.Listen(constant.NetworkTCP, l.listen.String())
	if err != nil {
		return fmt.Errorf("start tcp listener fail: %s", err)
	}
	l.dnsServer = &dns.Server{
		Listener:     l.tcpListener,
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
				l.fatalStartCloser(fmt.Errorf("start tcp listener fail: %s", err))
			}
			l.logger.Fatal(fmt.Sprintf("start tcp listener fail: %s", err))
		}
	}()
	waitLock.Lock()
	waitLock.Unlock()
	return nil
}

func (l *tcpListener) Close() error {
	err := l.tcpListener.Close()
	if err != nil {
		return fmt.Errorf("close tcp listener fail: %s", err)
	}
	return nil
}

func (l *tcpListener) Context() context.Context {
	return l.ctx
}

func (l *tcpListener) ContextLogger() log.ContextLogger {
	return l.logger
}

func (l *tcpListener) GetWorkflow() adapter.Workflow {
	return l.core.GetWorkflow(l.workflow)
}

func (l *tcpListener) ServeDNS(w dns.ResponseWriter, reqMsg *dns.Msg) {
	defer w.Close()
	ctx, respMsg := handler(l, reqMsg, w.RemoteAddr())
	if respMsg == nil {
		return
	}
	err := w.WriteMsg(respMsg)
	if err != nil {
		l.logger.ErrorContext(ctx, fmt.Sprintf("write msg fail: %s", err))
		return
	}
}
