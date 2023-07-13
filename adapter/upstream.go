package adapter

import (
	"context"

	"github.com/yaotthaha/cdns/log"

	"github.com/miekg/dns"
)

type Upstream interface {
	Type() string
	Tag() string
	ContextLogger() log.ContextLogger
	Exchange(ctx context.Context, dnsMsg *dns.Msg) (*dns.Msg, error)
	Dependencies() []string
}

type UpstreamExchangeWithDNSContext interface {
	Upstream
	ExchangeWithDNSContext(ctx context.Context, dnsMsg *dns.Msg, dnsCtx *DNSContext) (*dns.Msg, error)
}

type UpstreamGroup interface {
	Upstream
	IsUpstreamGroup()
	NowUpstream() Upstream
	AllUpstreams() []Upstream
}
