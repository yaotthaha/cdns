package adapter

import (
	"context"

	"github.com/yaotthaha/cdns/log"

	"github.com/miekg/dns"
)

type Core interface {
	Run() error
	Handle(context.Context, log.ContextLogger, Workflow, *DNSContext) (context.Context, *dns.Msg)
	GetUpstream(string) Upstream
	ListUpstream() []Upstream
	GetWorkflow(string) Workflow
	GetMatchPlugin(string) MatchPlugin
	GetExecPlugin(string) ExecPlugin
}

type WithCore interface {
	WithCore(Core)
}
