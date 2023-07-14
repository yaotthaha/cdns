package listener

import (
	"context"
	"crypto/tls"
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

var _ adapter.Listener = (*tlsListener)(nil)

type tlsListener struct {
	tag              string
	ctx              context.Context
	core             adapter.Core
	logger           log.ContextLogger
	fatalStartCloser func(error)
	listen           netip.AddrPort
	workflow         string
	tlsConfig        *tls.Config
	idleTimeout      time.Duration
	tlsListener      net.Listener
	dnsServer        *dns.Server
}

func NewTLSListener(ctx context.Context, core adapter.Core, logger log.ContextLogger, options listener.ListenerOptions) (adapter.Listener, error) {
	l := &tlsListener{
		tag:    options.Tag,
		ctx:    ctx,
		core:   core,
		logger: logger,
	}
	if options.TLSOptions == nil {
		return nil, fmt.Errorf("create tls listener fail: options is empty")
	}
	tlsOptions := options.TLSOptions
	listenAddr, err := parseBasicOptions(tlsOptions.Listen, 853)
	if err != nil {
		return nil, fmt.Errorf("create tls listener fail: %s", err)
	}
	l.listen = listenAddr
	tlsConfig := &tls.Config{}
	err = parseTLSOptions(tlsConfig, tlsOptions.TLSOption)
	if err != nil {
		return nil, fmt.Errorf("create tls listener fail: %s", err)
	}
	l.tlsConfig = tlsConfig
	if options.Workflow == "" {
		return nil, fmt.Errorf("create tls listener fail: workflow is empty")
	}
	l.workflow = options.Workflow
	if tlsOptions.IdleTimeout > 0 {
		l.idleTimeout = time.Duration(tlsOptions.IdleTimeout)
	}
	return l, nil
}

func (l *tlsListener) Tag() string {
	return l.tag
}

func (l *tlsListener) Type() string {
	return constant.ListenerTLS
}

func (l *tlsListener) WithFatalCloser(f func(err error)) {
	l.fatalStartCloser = f
}

func (l *tlsListener) Start() error {
	w := l.core.GetWorkflow(l.workflow)
	if w == nil {
		return fmt.Errorf("start tls listener fail: workflow %s not found", l.workflow)
	}
	tcpListener, err := net.Listen(constant.NetworkTCP, l.listen.String())
	if err != nil {
		return fmt.Errorf("start tls listener fail: %s", err)
	}
	l.tlsListener = tls.NewListener(tcpListener, l.tlsConfig)
	l.dnsServer = &dns.Server{
		Listener:     l.tlsListener,
		Handler:      l,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout: func() time.Duration {
			if l.idleTimeout > 0 {
				return l.idleTimeout
			}
			return 8 * time.Second
		},
	}
	waitLock := sync.Mutex{}
	waitLock.Lock()
	l.dnsServer.NotifyStartedFunc = waitLock.Unlock
	go func() {
		l.logger.Info(fmt.Sprintf("start tls listener on %s", l.listen.String()))
		err := l.dnsServer.ActivateAndServe()
		if err != nil {
			if tools.IsCloseOrCanceled(err) {
				return
			}
			if l.fatalStartCloser != nil {
				l.fatalStartCloser(fmt.Errorf("start tls listener fail: %s", err))
			}
			l.logger.Fatal(fmt.Sprintf("start tls listener fail: %s", err))
		}
	}()
	waitLock.Lock()
	waitLock.Unlock()
	return nil
}

func (l *tlsListener) Close() error {
	err := l.tlsListener.Close()
	if err != nil {
		return fmt.Errorf("close tls listener fail: %s", err)
	}
	return nil
}

func (l *tlsListener) Context() context.Context {
	return l.ctx
}

func (l *tlsListener) ContextLogger() log.ContextLogger {
	return l.logger
}

func (l *tlsListener) GetWorkflow() adapter.Workflow {
	return l.core.GetWorkflow(l.workflow)
}

func (l *tlsListener) ServeDNS(w dns.ResponseWriter, reqMsg *dns.Msg) {
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
