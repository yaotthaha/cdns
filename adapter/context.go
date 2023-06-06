package adapter

import (
	"net/netip"

	"github.com/miekg/dns"
)

type DNSContext struct {
	Listener     string
	ClientIP     netip.AddrPort
	Mark         uint64
	MetaData     map[string]any
	UsedWorkflow []Workflow
	UsedUpstream []Upstream
	ReqMsg       *dns.Msg
	RespMsg      *dns.Msg
}

func (d *DNSContext) WithUpstream(u Upstream) *DNSContext {
	if d.UsedUpstream == nil {
		d.UsedUpstream = make([]Upstream, 0)
	}
	d.UsedUpstream = append(d.UsedUpstream, u)
	return d
}

func (d *DNSContext) WithWorkflow(w Workflow) *DNSContext {
	if d.UsedWorkflow == nil {
		d.UsedWorkflow = make([]Workflow, 0)
	}
	d.UsedWorkflow = append(d.UsedWorkflow, w)
	return d
}

func (d *DNSContext) Clone() *DNSContext {
	newD := &DNSContext{
		Listener: d.Listener,
		ClientIP: d.ClientIP,
		Mark:     d.Mark,
		MetaData: d.MetaData, // Unsafe
	}
	if d.UsedWorkflow != nil {
		newD.UsedWorkflow = make([]Workflow, len(d.UsedWorkflow))
		copy(newD.UsedWorkflow, d.UsedWorkflow)
	}
	if d.UsedUpstream != nil {
		newD.UsedUpstream = make([]Upstream, len(d.UsedUpstream))
		copy(newD.UsedUpstream, d.UsedUpstream)
	}
	if d.ReqMsg != nil {
		newD.ReqMsg = d.ReqMsg.Copy()
	}
	if d.RespMsg != nil {
		newD.RespMsg = d.RespMsg.Copy()
	}
	return newD
}

func (d *DNSContext) SaveTo(dnsCtx *DNSContext) {
	dnsCtx.Listener = d.Listener
	dnsCtx.ClientIP = d.ClientIP
	dnsCtx.Mark = d.Mark
	dnsCtx.MetaData = d.MetaData
	if d.UsedWorkflow != nil {
		dnsCtx.UsedWorkflow = make([]Workflow, len(d.UsedWorkflow))
		copy(dnsCtx.UsedWorkflow, d.UsedWorkflow)
	}
	if d.UsedUpstream != nil {
		dnsCtx.UsedUpstream = make([]Upstream, len(d.UsedUpstream))
		copy(dnsCtx.UsedUpstream, d.UsedUpstream)
	}
	if d.ReqMsg != nil {
		dnsCtx.ReqMsg = d.ReqMsg.Copy()
	}
	if d.RespMsg != nil {
		dnsCtx.RespMsg = d.RespMsg.Copy()
	}
}
