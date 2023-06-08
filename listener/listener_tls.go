package listener

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
	"github.com/yaotthaha/cdns/lib/tools"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/listener"

	"github.com/miekg/dns"
)

type tlsListener struct {
	tag              string
	ctx              context.Context
	core             adapter.Core
	logger           log.ContextLogger
	fatalStartCloser func(error)
	listen           netip.AddrPort
	workflow         string
	tlsConfig        *tls.Config
	tlsListener      net.Listener
	dnsServer        *dns.Server
}

func NewTLSListener(ctx context.Context, core adapter.Core, logger log.Logger, options listener.ListenerOptions) (adapter.Listener, error) {
	l := &tlsListener{
		tag:    options.Tag,
		ctx:    ctx,
		core:   core,
		logger: log.NewContextLogger(log.NewTagLogger(logger, fmt.Sprintf("listener/%s/%s", constant.ListenerTLS, options.Tag))),
	}
	if options.Listen == "" {
		options.Listen = ":853"
	}
	host, port, err := net.SplitHostPort(options.Listen)
	if err != nil {
		return nil, fmt.Errorf("create tls listener fail: parse listen %s fail: %s", options.Listen, err)
	}
	if host == "" {
		host = "::"
	}
	options.Listen = net.JoinHostPort(host, port)
	listenAddr, err := netip.ParseAddrPort(options.Listen)
	if err != nil {
		return nil, fmt.Errorf("create tls listener fail: parse listen %s fail: %s", options.Listen, err)
	}
	l.listen = listenAddr
	if options.TLSOptions.CertFile == "" && options.TLSOptions.KeyFile == "" {
		return nil, fmt.Errorf("create tls listener fail: cert_file and key_file is empty")
	} else if options.TLSOptions.CertFile != "" && options.TLSOptions.KeyFile == "" {
		return nil, fmt.Errorf("create tls listener fail: key_file is empty")
	} else if options.TLSOptions.CertFile == "" && options.TLSOptions.KeyFile != "" {
		return nil, fmt.Errorf("create tls listener fail: cert_file is empty")
	} else {
		keyPair, err := tls.LoadX509KeyPair(options.TLSOptions.CertFile, options.TLSOptions.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("create tls listener fail: load key pair fail: %s", err)
		}
		tlsConfig := &tls.Config{}
		tlsConfig.Certificates = []tls.Certificate{keyPair}
		if options.TLSOptions.ClientCAFile != "" {
			caContent, err := os.ReadFile(options.TLSOptions.ClientCAFile)
			if err != nil {
				return nil, fmt.Errorf("create tls listener fail: load ca cert fail: %s", err)
			}
			tlsConfig.ClientCAs = &x509.CertPool{}
			if !tlsConfig.ClientCAs.AppendCertsFromPEM(caContent) {
				return nil, fmt.Errorf("create tls listener fail: append ca cert fail")
			}
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
		l.tlsConfig = tlsConfig
	}
	if options.Workflow == "" {
		return nil, fmt.Errorf("create tls listener fail: workflow is empty")
	}
	l.workflow = options.Workflow
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
