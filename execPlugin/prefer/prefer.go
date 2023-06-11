package prefer

import (
	"context"
	"fmt"
	"net/http"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/lib/tools"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/upstream"

	"github.com/miekg/dns"
)

const PluginType = "prefer"

var _ adapter.ExecPlugin = (*Prefer)(nil)

func init() {
	adapter.RegisterExecPlugin(PluginType, NewPrefer)
}

type Prefer struct {
	tag    string
	ctx    context.Context
	logger log.ContextLogger
}

func NewPrefer(tag string, args map[string]any) (adapter.ExecPlugin, error) {
	p := &Prefer{
		tag: tag,
	}

	return p, nil
}

func (p *Prefer) Tag() string {
	return p.tag
}

func (p *Prefer) Type() string {
	return PluginType
}

func (p *Prefer) Start() error {
	return nil
}

func (p *Prefer) Close() error {
	return nil
}

func (p *Prefer) WithContext(ctx context.Context) {
	p.ctx = ctx
}

func (p *Prefer) WithLogger(contextLogger log.ContextLogger) {
	p.logger = contextLogger
}

func (p *Prefer) WithCore(_ adapter.ExecPluginCore) {
}

func (p *Prefer) APIHandler() http.Handler {
	return nil
}

func (p *Prefer) Exec(ctx context.Context, args map[string]any, dnsCtx *adapter.DNSContext) bool {
	preferAny, ok := args["prefer"]
	if !ok {
		return true
	}
	prefer, ok := preferAny.(string)
	if !ok {
		p.logger.ErrorContext(ctx, "invalid prefer type")
		return true
	}
	switch prefer {
	case "4", "A", "a", "ipv4", "IPv4":
		prefer = "A"
	case "6", "AAAA", "aaaa", "ipv6", "IPv6":
		prefer = "AAAA"
	default:
		p.logger.ErrorContext(ctx, "invalid prefer type")
		return true
	}
	if dnsCtx.UsedUpstream == nil || len(dnsCtx.UsedUpstream) == 0 {
		return true
	}
	if dnsCtx.RespMsg == nil {
		return true
	}
	var (
		DNSTypeA    bool
		DNSTypeAAAA bool
	)
	for _, rr := range dnsCtx.RespMsg.Answer {
		switch rr.(type) {
		case *dns.A:
			DNSTypeA = true
		case *dns.AAAA:
			DNSTypeAAAA = true
		}
	}
	if DNSTypeA == DNSTypeAAAA {
		return true
	}
	if DNSTypeA && prefer == "AAAA" {
		reqAAAADNSMsg := &dns.Msg{}
		reqAAAADNSMsg.SetQuestion(dns.Fqdn(dnsCtx.ReqMsg.Question[0].Name), dns.TypeAAAA)
		up := dnsCtx.UsedUpstream[len(dnsCtx.UsedUpstream)-1]
		if up == nil {
			return true
		}
		respAAAADNSMsg, err := upstream.RetryUpstream(ctx, up, reqAAAADNSMsg, nil)
		if err != nil {
			p.logger.ErrorContext(ctx, fmt.Sprintf("prefer AAAA fail: dns query fail"))
			return true
		}
		select {
		case <-ctx.Done():
			return false
		default:
		}
		var hasAAAA bool
		for _, rr := range respAAAADNSMsg.Answer {
			if _, ok := rr.(*dns.AAAA); ok {
				hasAAAA = true
				break
			}
		}
		if hasAAAA {
			newRespMsg := &dns.Msg{}
			newRespMsg.SetRcode(dnsCtx.ReqMsg, dns.RcodeSuccess)
			var name string
			if len(dnsCtx.ReqMsg.Question) > 1 {
				name = dnsCtx.ReqMsg.Question[0].Name
			}
			newRespMsg.Ns = []dns.RR{tools.FakeSOA(name)}
			dnsCtx.RespMsg = newRespMsg
			p.logger.DebugContext(ctx, "prefer AAAA, remove answer")
		}
	}
	if DNSTypeAAAA && prefer == "A" {
		reqADNSMsg := &dns.Msg{}
		reqADNSMsg.SetQuestion(dns.Fqdn(dnsCtx.ReqMsg.Question[0].Name), dns.TypeA)
		up := dnsCtx.UsedUpstream[len(dnsCtx.UsedUpstream)-1]
		if up == nil {
			return true
		}
		respADNSMsg, err := upstream.RetryUpstream(ctx, up, reqADNSMsg, nil)
		if err != nil {
			p.logger.ErrorContext(ctx, fmt.Sprintf("prefer A fail: dns query fail"))
			return true
		}
		select {
		case <-ctx.Done():
			return false
		default:
		}
		var hasA bool
		for _, rr := range respADNSMsg.Answer {
			if _, ok := rr.(*dns.A); ok {
				hasA = true
				break
			}
		}
		if hasA {
			newRespMsg := &dns.Msg{}
			newRespMsg.SetRcode(dnsCtx.ReqMsg, dns.RcodeSuccess)
			var name string
			if len(dnsCtx.ReqMsg.Question) > 1 {
				name = dnsCtx.ReqMsg.Question[0].Name
			}
			newRespMsg.Ns = []dns.RR{tools.FakeSOA(name)}
			dnsCtx.RespMsg = newRespMsg
			p.logger.DebugContext(ctx, "prefer A, remove answer")
		}
	}
	return true
}
