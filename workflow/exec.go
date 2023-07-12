package workflow

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/lib/tools"
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
	setTTL   *uint32
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
			eItem.jumpTo[i] = jumpTo
		}
		rn++
	}

	if options.GoTo != nil {
		eItem.goTo = options.GoTo
		rn++
	}

	if options.SetTTL != nil {
		eItem.setTTL = options.SetTTL
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
		if dnsCtx.BeforeUpstreamHook.Len() > 0 {
			beforeHookFuncList := make([]*adapter.BeforeUpstreamHookFunc, 0)
			dnsCtx.BeforeUpstreamHook.Range(func(_ int, hookFunc *adapter.BeforeUpstreamHookFunc) bool {
				beforeHookFuncList = append(beforeHookFuncList, hookFunc)
				return true
			})
			for _, hookFunc := range beforeHookFuncList {
				if hookFunc != nil {
					(*hookFunc)(ctx, dnsCtx)
				}
			}
		}
		logger.DebugContext(ctx, fmt.Sprintf("sends to upstream: %s", *e.upstream))
		u := e.core.GetUpstream(*e.upstream)
		dnsCtx.UsedUpstream.Append(u)
		retry := 3
		extraMsgs := make([]*adapter.ExtraDNSMsg, 0)
		reqQueue := make([]*dns.Msg, 0)
		var respQueueLock sync.Mutex
		if dnsCtx.ExtraDNSMsgMap.Len() > 0 {
			dnsCtx.ExtraDNSMsgMap.Range(func(key string, value *adapter.ExtraDNSMsg) bool {
				extraMsgs = append(extraMsgs, value)
				return true
			})
		}
		if len(extraMsgs) > 0 {
			for _, extraMsg := range extraMsgs {
				reqQueue = append(reqQueue, extraMsg.ReqMsg)
			}
		}
		reqQueue = append(reqQueue, dnsCtx.ReqMsg)
		respQueue := make([]*dns.Msg, len(reqQueue))
		wg := sync.WaitGroup{}
		for i, req := range reqQueue {
			wg.Add(1)
			go func(index int, req *dns.Msg) {
				defer wg.Done()
				for i := 0; i < retry; i++ {
					respMsg, err := upstream.Exchange(ctx, u, dnsCtx, req)
					if err == nil {
						respQueueLock.Lock()
						respQueue[index] = respMsg
						respQueueLock.Unlock()
						break
					}
					u.ContextLogger().DebugContext(ctx, fmt.Sprintf("retry %d: %s", i+1, req.Question[0].String()))
				}
			}(i, req)
		}
		wg.Wait()
		if len(extraMsgs) > 0 {
			for i, extraMsg := range extraMsgs {
				extraMsg.RespMsg = respQueue[i]
			}
		}
		dnsCtx.RespMsg = respQueue[len(respQueue)-1]
		if dnsCtx.AfterUpstreamHook.Len() > 0 {
			afterHookFuncList := make([]*adapter.AfterUpstreamHookFunc, 0)
			dnsCtx.AfterUpstreamHook.Range(func(_ int, hookFunc *adapter.AfterUpstreamHookFunc) bool {
				afterHookFuncList = append(afterHookFuncList, hookFunc)
				return true
			})
			for _, hookFunc := range afterHookFuncList {
				if hookFunc != nil {
					(*hookFunc)(ctx, dnsCtx)
				}
			}
		}
	}
	if e.plugin != nil {
		logger.DebugContext(ctx, fmt.Sprintf("exec plugin: %s, args: %+v", e.plugin.plugin.Tag(), e.plugin.args))
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
		w.Exec(ctx, dnsCtx)
		return false
	}
	if e.setTTL != nil {
		if *e.setTTL > 0 && dnsCtx.RespMsg != nil {
			for _, answer := range dnsCtx.RespMsg.Answer {
				answer.Header().Ttl = *e.setTTL
			}
		}
	}
	if e.clean != nil {
		if *e.clean {
			dnsCtx.RespMsg = nil
			logger.DebugContext(ctx, "clean resp-msg")
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
				name := dnsCtx.ReqMsg.Question[0].Name
				dnsCtx.RespMsg.Ns = []dns.RR{tools.FakeSOA(name)}
				logger.DebugContext(ctx, "return success")
				done = true
			case "FAIL":
				dnsCtx.RespMsg = &dns.Msg{}
				dnsCtx.RespMsg.SetRcode(dnsCtx.ReqMsg, dns.RcodeServerFailure)
				name := dnsCtx.ReqMsg.Question[0].Name
				dnsCtx.RespMsg.Ns = []dns.RR{tools.FakeSOA(name)}
				logger.DebugContext(ctx, "return fail")
				done = true
			case "NXDOMAIN":
				dnsCtx.RespMsg = &dns.Msg{}
				dnsCtx.RespMsg.SetRcode(dnsCtx.ReqMsg, dns.RcodeNameError)
				name := dnsCtx.ReqMsg.Question[0].Name
				dnsCtx.RespMsg.Ns = []dns.RR{tools.FakeSOA(name)}
				logger.DebugContext(ctx, "return nxdomain")
				done = true
			case "REJECT":
				dnsCtx.RespMsg = &dns.Msg{}
				dnsCtx.RespMsg.SetRcode(dnsCtx.ReqMsg, dns.RcodeRefused)
				name := dnsCtx.ReqMsg.Question[0].Name
				dnsCtx.RespMsg.Ns = []dns.RR{tools.FakeSOA(name)}
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
