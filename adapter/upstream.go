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
}
