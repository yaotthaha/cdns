package adapter

import (
	"net/netip"

	"github.com/miekg/dns"
)

type DNSContext struct {
	Listener     string
	ClientIP     netip.AddrPort
	Mark         uint64
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
