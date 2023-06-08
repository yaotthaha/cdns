package listener

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/lib/tools"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/listener"

	"github.com/miekg/dns"
)

func NewListener(ctx context.Context, core adapter.Core, logger log.Logger, options listener.ListenerOptions) (adapter.Listener, error) {
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

func handler(h adapter.Listener, reqMsg *dns.Msg, remoteIP netip.Addr) (context.Context, *dns.Msg) {
	defer func() {
		err := recover()
		if err != nil {
			h.ContextLogger().Fatal(fmt.Sprintf("panic: %s", err))
		}
	}()
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
	if dnsCtx.RespMsg == nil {
		dnsCtx.RespMsg = &dns.Msg{}
		dnsCtx.RespMsg.SetRcode(reqMsg, dns.RcodeServerFailure)
		var name string
		if len(dnsCtx.ReqMsg.Question) > 1 {
			name = dnsCtx.ReqMsg.Question[0].Name
		}
		dnsCtx.RespMsg.Ns = []dns.RR{tools.FakeSOA(name)}
	}
	/**
	qStrs := make([]string, len(dnsCtx.RespMsg.Question))
	for i, q := range dnsCtx.RespMsg.Question {
		qStrs[i] = q.String()
	}
	logger.DebugContext(ctx, fmt.Sprintf("response: question: [%s], answers: [%s]", strings.Join(qStrs, " | "), tools.Join(dnsCtx.RespMsg.Answer, " | ")))
	*/
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
