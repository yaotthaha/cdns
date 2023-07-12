package adapter

import (
	"context"
	"net/netip"

	"github.com/yaotthaha/cdns/lib/types"

	"github.com/miekg/dns"
)

type (
	BeforeUpstreamHookFunc func(ctx context.Context, dnsCtx *DNSContext)
	AfterUpstreamHookFunc  func(ctx context.Context, dnsCtx *DNSContext)
)

type (
	PreUpstreamHookFunc  func(ctx context.Context, upstream Upstream, dnsReq *dns.Msg, dnsCtx *DNSContext)
	PostUpstreamHookFunc func(ctx context.Context, upstream Upstream, dnsReq *dns.Msg, dnsResp *dns.Msg, dnsErr error, dnsCtx *DNSContext)
)

type ExtraDNSMsg struct {
	ReqMsg  *dns.Msg
	RespMsg *dns.Msg
}

func (e *ExtraDNSMsg) Clone() types.CloneableValue {
	return &ExtraDNSMsg{
		ReqMsg:  e.ReqMsg.Copy(),
		RespMsg: e.RespMsg.Copy(),
	}
}

func (e *ExtraDNSMsg) Value() any {
	return e
}

type DNSContext struct {
	Listener           string
	ClientIP           netip.Addr
	Mark               uint64
	MetaData           types.CloneableSyncMap[string, types.CloneableValue]
	UsedWorkflow       *types.List[Workflow]
	UsedUpstream       *types.List[Upstream]
	ReqMsg             *dns.Msg
	RespMsg            *dns.Msg
	ExtraDNSMsgMap     types.CloneableSyncMap[string, *ExtraDNSMsg]
	BeforeUpstreamHook *types.List[*BeforeUpstreamHookFunc]
	AfterUpstreamHook  *types.List[*AfterUpstreamHookFunc]
	PreUpstreamHook    *types.List[*PreUpstreamHookFunc]
	PostUpstreamHook   *types.List[*PostUpstreamHookFunc]
}

func NewDNSContext() *DNSContext {
	return &DNSContext{
		MetaData:           types.CloneableSyncMap[string, types.CloneableValue]{},
		UsedWorkflow:       types.NewList[Workflow](),
		UsedUpstream:       types.NewList[Upstream](),
		ExtraDNSMsgMap:     types.CloneableSyncMap[string, *ExtraDNSMsg]{},
		BeforeUpstreamHook: types.NewList[*BeforeUpstreamHookFunc](),
		AfterUpstreamHook:  types.NewList[*AfterUpstreamHookFunc](),
		PreUpstreamHook:    types.NewList[*PreUpstreamHookFunc](),
		PostUpstreamHook:   types.NewList[*PostUpstreamHookFunc](),
	}
}

func (d *DNSContext) Clone() *DNSContext {
	newD := &DNSContext{}
	d.SaveTo(newD)
	return newD
}

func (d *DNSContext) SaveTo(dnsCtx *DNSContext) {
	dnsCtx.Listener = d.Listener
	dnsCtx.ClientIP = d.ClientIP
	dnsCtx.Mark = d.Mark
	dnsCtx.MetaData = *d.MetaData.Clone()
	dnsCtx.ExtraDNSMsgMap = *d.ExtraDNSMsgMap.Clone()
	if d.UsedWorkflow != nil {
		dnsCtx.UsedWorkflow = d.UsedWorkflow.Clone()
	}
	if d.UsedUpstream != nil {
		dnsCtx.UsedUpstream = d.UsedUpstream.Clone()
	}
	if d.ReqMsg != nil {
		dnsCtx.ReqMsg = d.ReqMsg.Copy()
	}
	if d.RespMsg != nil {
		dnsCtx.RespMsg = d.RespMsg.Copy()
	}
	if d.BeforeUpstreamHook != nil {
		dnsCtx.BeforeUpstreamHook = d.BeforeUpstreamHook.Clone()
	}
	if d.AfterUpstreamHook != nil {
		dnsCtx.AfterUpstreamHook = d.AfterUpstreamHook.Clone()
	}
	if d.PreUpstreamHook != nil {
		dnsCtx.PreUpstreamHook = d.PreUpstreamHook.Clone()
	}
	if d.PostUpstreamHook != nil {
		dnsCtx.PostUpstreamHook = d.PostUpstreamHook.Clone()
	}
}
