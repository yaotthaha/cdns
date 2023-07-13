package adapter

import (
	"context"

	"github.com/yaotthaha/cdns/log"

	"github.com/miekg/dns"
)

type Core interface {
	Run() error
	Handle(ctx context.Context, logger log.ContextLogger, workflow Workflow, dnsCtx *DNSContext) (context.Context, *dns.Msg)
	GetUpstream(tag string) Upstream
	ListUpstream() []Upstream
	GetWorkflow(tag string) Workflow
	GetMatchPlugin(tag string) MatchPlugin
	GetExecPlugin(tag string) ExecPlugin
}

type WithCore interface {
	WithCore(Core)
}
