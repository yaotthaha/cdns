package listener

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
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
	default:
		return nil, fmt.Errorf("listener type %s not supported", options.Type)
	}
}

func handler(h adapter.Listener, reqBytes []byte, remoteAddr net.Addr) (context.Context, []byte) {
	logger := h.ContextLogger()
	tag := h.Tag()
	ctx := h.Context()
	workflow := h.GetWorkflow()
	reqMsg := &dns.Msg{}
	err := reqMsg.Unpack(reqBytes)
	if err != nil {
		logger.Error(fmt.Sprintf("unpack error: %s", err))
		return ctx, nil
	}
	dnsCtx := &adapter.DNSContext{}
	dnsCtx.Listener = tag
	dnsCtx.ReqMsg = reqMsg
	dnsCtx.ClientIP = parseNetAddrToNetIPAddrPort(remoteAddr)
	ctx = log.AddContextTag(ctx)
	logger.InfoContext(ctx, fmt.Sprintf("receive request from %s, qtype: %s, qname: %s", dnsCtx.ClientIP.String(), dns.TypeToString[reqMsg.Question[0].Qtype], reqMsg.Question[0].Name))
	workflow.Exec(ctx, dnsCtx)
	if dnsCtx.RespMsg == nil {
		dnsCtx.RespMsg = &dns.Msg{}
		dnsCtx.RespMsg.SetRcode(reqMsg, dns.RcodeServerFailure)
	}
	respBytes, err := dnsCtx.RespMsg.Pack()
	if err != nil {
		logger.ErrorContext(ctx, fmt.Sprintf("pack fail: %s", err))
		return ctx, nil
	}
	return ctx, respBytes
}

func parseNetAddrToNetIPAddrPort(addr net.Addr) netip.AddrPort {
	switch v := addr.(type) {
	case *net.UDPAddr:
		addrPort, _ := netip.ParseAddrPort(v.String())
		return addrPort
	case *net.TCPAddr:
		addrPort, _ := netip.ParseAddrPort(v.String())
		return addrPort
	default:
		return netip.AddrPort{}
	}
}
