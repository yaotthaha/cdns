package workflow

import (
	"context"
	"fmt"
	"strings"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/workflow"
	"github.com/yaotthaha/cdns/upstream"

	"github.com/miekg/dns"
)

type execItem struct {
	core     adapter.Core
	setMark  *uint64
	upstream *string
	plugin   *execPlugin
	jumpTo   []string
	goTo     *string
	clean    *bool
	reTurn   any
}

type execPlugin struct {
	plugin adapter.ExecPlugin
	args   map[string]any
}

func newExecItem(core adapter.Core, options workflow.RuleExecItem) (*execItem, error) {
	eItem := &execItem{
		core: core,
	}
	rn := 0

	if options.Mark != nil {
		eItem.setMark = options.Mark
		rn++
	}

	if options.Upstream != nil {
		if core.GetUpstream(*options.Upstream) == nil {
			return nil, fmt.Errorf("upstream %s not found", *options.Upstream)
		}
		eItem.upstream = options.Upstream
		rn++
	}

	if options.Plugin != nil {
		plugin := core.GetExecPlugin(options.Plugin.Tag)
		if plugin == nil {
			return nil, fmt.Errorf("exec plugin %s not found", options.Plugin.Tag)
		}
		execPlugin := &execPlugin{
			plugin: plugin,
			args:   options.Plugin.Args,
		}
		eItem.plugin = execPlugin
		rn++
	}

	if options.JumpTo != nil && len(*options.JumpTo) > 0 {
		eItem.jumpTo = make([]string, len(*options.JumpTo))
		for i, jumpTo := range *options.JumpTo {
			w := core.GetWorkflow(jumpTo)
			if w == nil {
				return nil, fmt.Errorf("workflow %s not found", jumpTo)
			}
			eItem.jumpTo[i] = jumpTo
		}
		rn++
	}

	if options.GoTo != nil {
		w := core.GetWorkflow(*options.GoTo)
		if w == nil {
			return nil, fmt.Errorf("workflow %s not found", *options.GoTo)
		}
		eItem.goTo = options.GoTo
		rn++
	}

	if options.Clean != nil {
		eItem.clean = options.Clean
		rn++
	}

	if options.Return != nil {
		eItem.reTurn = options.Return
		rn++
	}

	if rn == 0 {
		return nil, fmt.Errorf("invalid exec rule: no rule")
	}
	if rn > 1 {
		return nil, fmt.Errorf("invalid exec rule: more than one rule")
	}

	return eItem, nil
}

func (e *execItem) exec(ctx context.Context, logger log.ContextLogger, dnsCtx *adapter.DNSContext) bool {
	if e.setMark != nil {
		logger.DebugContext(ctx, fmt.Sprintf("set mark: %d ==> %d", dnsCtx.Mark, *e.setMark))
		dnsCtx.Mark = *e.setMark
	}
	if e.upstream != nil {
		u := e.core.GetUpstream(*e.upstream)
		dnsCtx.WithUpstream(u)
		respMsg, err := upstream.RetryUpstream(ctx, u, dnsCtx.ReqMsg)
		if err == nil {
			dnsCtx.RespMsg = respMsg
		}
	}
	if e.plugin != nil {
		if !e.plugin.plugin.Exec(ctx, e.plugin.args, dnsCtx) {
			return false
		}
	}
	if e.jumpTo != nil {
		for _, j := range e.jumpTo {
			w := e.core.GetWorkflow(j)
			if w == nil {
				logger.ErrorContext(ctx, fmt.Sprintf("workflow %s not found", j))
				return false
			}
			logger.DebugContext(ctx, fmt.Sprintf("jump to => %s", j))
			if !w.Exec(ctx, dnsCtx) {
				return false
			}
		}
	}
	if e.goTo != nil {
		w := e.core.GetWorkflow(*e.goTo)
		if w == nil {
			logger.ErrorContext(ctx, fmt.Sprintf("workflow %s not found", *e.goTo))
			return false
		}
		logger.DebugContext(ctx, fmt.Sprintf("go to => %s", *e.goTo))
		if !w.Exec(ctx, dnsCtx) {
			return false
		}
	}
	if e.clean != nil {
		if *e.clean {
			dnsCtx.RespMsg = nil
			logger.DebugContext(ctx, "clean resp_msg")
		}
	}
	if e.reTurn != nil {
		done := false
		switch r := e.reTurn.(type) {
		case string:
			r = strings.ToUpper(r)
			switch r {
			case "SUCCESS":
				dnsCtx.RespMsg = &dns.Msg{}
				dnsCtx.RespMsg.SetRcode(dnsCtx.ReqMsg, dns.RcodeSuccess)
				logger.DebugContext(ctx, "return success")
				done = true
			case "FAIL":
				dnsCtx.RespMsg = &dns.Msg{}
				dnsCtx.RespMsg.SetRcode(dnsCtx.ReqMsg, dns.RcodeServerFailure)
				logger.DebugContext(ctx, "return fail")
				done = true
			case "REJECT":
				dnsCtx.RespMsg = &dns.Msg{}
				dnsCtx.RespMsg.SetRcode(dnsCtx.ReqMsg, dns.RcodeRefused)
				logger.DebugContext(ctx, "return reject")
				done = true
			}
		}
		if !done {
			logger.DebugContext(ctx, "return")
		}
		return false
	}
	return true
}
