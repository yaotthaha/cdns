package listener

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/lib/tools"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/listener"

	"github.com/miekg/dns"
)

func NewListener(ctx context.Context, core adapter.Core, logger log.ContextLogger, options listener.ListenerOptions) (adapter.Listener, error) {
	switch options.Type {
	case constant.ListenerUDP:
		return NewUDPListener(ctx, core, logger, options)
	case constant.ListenerTCP:
		return NewTCPListener(ctx, core, logger, options)
	case constant.ListenerTLS:
		return NewTLSListener(ctx, core, logger, options)
	case constant.ListenerHTTP:
		return NewHTTPListener(ctx, core, logger, options)
	default:
		return nil, fmt.Errorf("listener type %s not supported", options.Type)
	}
}

func parseBasicOptions(listen string, defaultPort uint16) (netip.AddrPort, error) {
	if listen == "" {
		listen = fmt.Sprintf(":%s", strconv.Itoa(int(defaultPort)))
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if host == "" {
		host = "::"
	}
	listen = net.JoinHostPort(host, port)
	listenAddr, err := netip.ParseAddrPort(listen)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return listenAddr, nil
}

func parseTLSOptions(tlsConfig *tls.Config, options listener.TLSOptions) error {
	if options.CertFile == "" && options.KeyFile == "" {
		return fmt.Errorf("cert-file and key-file is empty")
	} else if options.CertFile != "" && options.KeyFile == "" {
		return fmt.Errorf("key-file is empty")
	} else if options.CertFile == "" && options.KeyFile != "" {
		return fmt.Errorf("cert-file is empty")
	}
	keyPair, err := tls.LoadX509KeyPair(options.CertFile, options.KeyFile)
	if err != nil {
		return fmt.Errorf("load key pair fail: %s", err)
	}
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	tlsConfig.Certificates = []tls.Certificate{keyPair}
	if options.ClientCAFile != nil && len(options.ClientCAFile) > 0 {
		tlsConfig.ClientCAs = x509.NewCertPool()
		for _, f := range options.ClientCAFile {
			caContent, err := os.ReadFile(f)
			if err != nil {
				return fmt.Errorf("file: %s, load ca cert fail: %s", f, err)
			}
			if !tlsConfig.ClientCAs.AppendCertsFromPEM(caContent) {
				return fmt.Errorf("file: %s, append ca cert fail", f)
			}
		}
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return nil
}

func handler(h adapter.Listener, reqMsg *dns.Msg, remoteIP netip.Addr) (context.Context, *dns.Msg) {
	logger := h.ContextLogger()
	tag := h.Tag()
	ctx := h.Context()
	workflow := h.GetWorkflow()
	dnsCtx := &adapter.DNSContext{}
	dnsCtx.Listener = tag
	dnsCtx.ReqMsg = reqMsg
	dnsCtx.ClientIP = remoteIP
	ctx = log.AddContextTag(ctx)
	logger.InfoContext(ctx, fmt.Sprintf("receive request from %s, qtype: %s, qname: %s", dnsCtx.ClientIP.String(), dns.TypeToString[reqMsg.Question[0].Qtype], reqMsg.Question[0].Name))
	workflow.Exec(ctx, dnsCtx)
	defer func() {
		err := recover()
		if err != nil {
			h.ContextLogger().PrintContext(ctx, "Panic", fmt.Sprintf("panic: %s", err))
			var stackBuf []byte
			n := runtime.Stack(stackBuf, false)
			h.ContextLogger().PrintContext(ctx, "Panic", fmt.Sprintf("stack: %s", stackBuf[:n]))
		}
	}()
	if dnsCtx.RespMsg == nil {
		dnsCtx.RespMsg = &dns.Msg{}
		dnsCtx.RespMsg.SetRcode(reqMsg, dns.RcodeServerFailure)
		var name string
		if len(dnsCtx.ReqMsg.Question) > 1 {
			name = dnsCtx.ReqMsg.Question[0].Name
		}
		dnsCtx.RespMsg.Ns = []dns.RR{tools.FakeSOA(name)}
	}
	return ctx, dnsCtx.RespMsg
}

func strToNetIPAddr(str string) netip.Addr {
	if str == "" {
		return netip.Addr{}
	}
	ip, err := netip.ParseAddr(str)
	if err == nil {
		return ip
	}
	addr, err := netip.ParseAddrPort(str)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Addr()
}
