package prefer

import (
	"context"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/lib/tools"
	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/log"

	"github.com/miekg/dns"
)

const PluginType = "prefer"

const (
	MetaDataKey = "prefer"
	ExtraKey    = "prefer"
)

var (
	_ adapter.ExecPlugin        = (*Prefer)(nil)
	_ adapter.WithContext       = (*Prefer)(nil)
	_ adapter.WithContextLogger = (*Prefer)(nil)
)

func init() {
	adapter.RegisterExecPlugin(PluginType, NewPrefer)
}

type Prefer struct {
	tag                 string
	ctx                 context.Context
	logger              log.ContextLogger
	preHookFuncPointer  *func(ctx context.Context, dnsCtx *adapter.DNSContext)
	postHookFuncPointer *func(ctx context.Context, dnsCtx *adapter.DNSContext)
}

func NewPrefer(tag string, _ map[string]any) (adapter.ExecPlugin, error) {
	p := &Prefer{
		tag: tag,
	}
	preHookFunc := p.PreHook
	postHookFunc := p.PostHook
	p.preHookFuncPointer = &preHookFunc
	p.postHookFuncPointer = &postHookFunc
	return p, nil
}

func (p *Prefer) Tag() string {
	return p.tag
}

func (p *Prefer) Type() string {
	return PluginType
}

func (p *Prefer) WithContext(ctx context.Context) {
	p.ctx = ctx
}

func (p *Prefer) WithContextLogger(contextLogger log.ContextLogger) {
	p.logger = contextLogger
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
	preferType := uint16(0)
	switch prefer {
	case "A", "a", "ipv4", "IPv4":
		preferType = dns.TypeA
	case "AAAA", "aaaa", "ipv6", "IPv6":
		preferType = dns.TypeAAAA
	default:
		p.logger.ErrorContext(ctx, "invalid prefer type")
		return true
	}
	dnsCtx.MetaData.Store(MetaDataKey, types.NewCloneableValue(preferType))
	dnsCtx.PreHook.Append((*adapter.HookFunc)(p.preHookFuncPointer))
	dnsCtx.PostHook.Append((*adapter.HookFunc)(p.postHookFuncPointer))
	return true
}

func (p *Prefer) PreHook(ctx context.Context, dnsCtx *adapter.DNSContext) {
	var _type uint16
	if dnsCtx.ReqMsg.Question[0].Qtype != dns.TypeA && dnsCtx.ReqMsg.Question[0].Qtype != dns.TypeAAAA {
		return
	} else {
		_type = dnsCtx.ReqMsg.Question[0].Qtype
	}
	preferValue, ok := dnsCtx.MetaData.Load(MetaDataKey)
	if !ok {
		return
	}
	prefer := preferValue.Value().(uint16)
	if _type == dns.TypeA && prefer == dns.TypeAAAA {
		newMsg := new(dns.Msg)
		dnsCtx.ReqMsg.CopyTo(newMsg)
		newMsg.Question[0].Qtype = dns.TypeAAAA
		dnsCtx.ExtraDNSMsgMap.Store(ExtraKey, &adapter.ExtraDNSMsg{
			ReqMsg: newMsg,
		})
		p.logger.DebugContext(ctx, "prefer AAAA")
		dnsCtx.PreHook.DelV((*adapter.HookFunc)(p.preHookFuncPointer))
	}
	if _type == dns.TypeAAAA && prefer == dns.TypeA {
		newMsg := new(dns.Msg)
		dnsCtx.ReqMsg.CopyTo(newMsg)
		newMsg.Question[0].Qtype = dns.TypeA
		dnsCtx.ExtraDNSMsgMap.Store(ExtraKey, &adapter.ExtraDNSMsg{
			ReqMsg: newMsg,
		})
		p.logger.DebugContext(ctx, "prefer A")
		dnsCtx.PreHook.DelV((*adapter.HookFunc)(p.preHookFuncPointer))
	}
}

func (p *Prefer) PostHook(ctx context.Context, dnsCtx *adapter.DNSContext) {
	var _type uint16
	if dnsCtx.ReqMsg.Question[0].Qtype != dns.TypeA && dnsCtx.ReqMsg.Question[0].Qtype != dns.TypeAAAA {
		return
	} else {
		_type = dnsCtx.ReqMsg.Question[0].Qtype
	}
	defer func() {
		dnsCtx.MetaData.Delete(MetaDataKey)
	}()
	preferAny, ok := dnsCtx.MetaData.Load(MetaDataKey)
	if !ok {
		return
	}
	extraDNSMsg, ok := dnsCtx.ExtraDNSMsgMap.LoadAndDelete(ExtraKey)
	if !ok {
		return
	}
	if extraDNSMsg.RespMsg == nil && dnsCtx.RespMsg == nil {
		return
	}
	prefer := preferAny.Value().(uint16)
	if prefer == dns.TypeAAAA && _type == dns.TypeA && extraDNSMsg.RespMsg != nil {
		aaaa := false
		for _, rr := range extraDNSMsg.RespMsg.Answer {
			if _, ok := rr.(*dns.AAAA); ok {
				aaaa = true
				break
			}
		}
		if aaaa {
			a := false
			for _, rr := range dnsCtx.RespMsg.Answer {
				if _, ok := rr.(*dns.A); ok {
					a = true
					break
				}
			}
			if !a {
				return
			}
			newRespMsg := new(dns.Msg)
			newRespMsg.SetRcode(dnsCtx.ReqMsg, dns.RcodeSuccess)
			var name string
			if len(dnsCtx.ReqMsg.Question) > 1 {
				name = dnsCtx.ReqMsg.Question[0].Name
			}
			newRespMsg.Ns = []dns.RR{tools.FakeSOA(name)}
			dnsCtx.RespMsg = newRespMsg
			p.logger.DebugContext(ctx, "prefer AAAA, remove answer")
			dnsCtx.PostHook.DelV((*adapter.HookFunc)(p.postHookFuncPointer))
		}
	}
	if prefer == dns.TypeA && _type == dns.TypeAAAA && extraDNSMsg.RespMsg != nil {
		a := false
		for _, rr := range extraDNSMsg.RespMsg.Answer {
			if _, ok := rr.(*dns.A); ok {
				a = true
				break
			}
		}
		if a {
			aaaa := false
			for _, rr := range dnsCtx.RespMsg.Answer {
				if _, ok := rr.(*dns.AAAA); ok {
					aaaa = true
					break
				}
			}
			if !aaaa {
				return
			}
			newRespMsg := new(dns.Msg)
			newRespMsg.SetRcode(dnsCtx.ReqMsg, dns.RcodeSuccess)
			var name string
			if len(dnsCtx.ReqMsg.Question) > 1 {
				name = dnsCtx.ReqMsg.Question[0].Name
			}
			newRespMsg.Ns = []dns.RR{tools.FakeSOA(name)}
			dnsCtx.RespMsg = newRespMsg
			p.logger.DebugContext(ctx, "prefer A, remove answer")
			dnsCtx.PostHook.DelV((*adapter.HookFunc)(p.postHookFuncPointer))
		}
	}
}
