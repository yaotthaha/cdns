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

var _ adapter.Listener = (*tcpListener)(nil)

type tcpListener struct {
	tag              string
	ctx              context.Context
	core             adapter.Core
	logger           log.ContextLogger
	fatalStartCloser func(error)
	listen           netip.AddrPort
	idleTimeout      time.Duration
	workflow         string
	tcpListener      net.Listener
	dnsServer        *dns.Server
}

func NewTCPListener(ctx context.Context, core adapter.Core, logger log.ContextLogger, options listener.ListenerOptions) (adapter.Listener, error) {
	l := &tcpListener{
		tag:    options.Tag,
		ctx:    ctx,
		core:   core,
		logger: logger,
	}
	if options.TCPOptions == nil {
		return nil, fmt.Errorf("create tcp listener fail: options is empty")
	}
	tcpOptions := options.TCPOptions
	listenAddr, err := parseBasicOptions(tcpOptions.Listen, 53)
	if err != nil {
		return nil, fmt.Errorf("create tcp listener fail: %s", err)
	}
	l.listen = listenAddr
	if options.Workflow == "" {
		return nil, fmt.Errorf("create tcp listener fail: workflow is empty")
	}
	l.workflow = options.Workflow
	if tcpOptions.IdleTimeout > 0 {
		l.idleTimeout = time.Duration(tcpOptions.IdleTimeout)
	}
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
		IdleTimeout: func() time.Duration {
			if l.idleTimeout > 0 {
				return l.idleTimeout
			} else {
				return 8 * time.Second
			}
		},
	}
	waitLock := sync.Mutex{}
	waitLock.Lock()
	l.dnsServer.NotifyStartedFunc = waitLock.Unlock
	go func() {
		l.logger.Info(fmt.Sprintf("start tcp listener on %s", l.listen.String()))
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
	ctx, respMsg := handler(l.core, l, reqMsg, strToNetIPAddr(w.RemoteAddr().String()))
	if respMsg == nil {
		return
	}
	err := w.WriteMsg(respMsg)
	if err != nil {
		l.logger.ErrorContext(ctx, fmt.Sprintf("write msg fail: %s", err))
		return
	}
}
