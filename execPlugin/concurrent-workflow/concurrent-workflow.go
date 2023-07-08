package concurrent_workflow

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/log"
)

const PluginType = "concurrent-workflow"

var (
	_ adapter.ExecPlugin         = (*ConcurrentWorkflow)(nil)
	_ adapter.WithContext        = (*ConcurrentWorkflow)(nil)
	_ adapter.WithContextLogger  = (*ConcurrentWorkflow)(nil)
	_ adapter.WithExecPluginCore = (*ConcurrentWorkflow)(nil)
)

func init() {
	adapter.RegisterExecPlugin(PluginType, NewConcurrentWorkflow)
}

type ConcurrentWorkflow struct {
	tag    string
	ctx    context.Context
	logger log.ContextLogger
	core   adapter.ExecPluginCore
}

func NewConcurrentWorkflow(tag string, _ map[string]any) (adapter.ExecPlugin, error) {
	w := &ConcurrentWorkflow{
		tag: tag,
	}
	return w, nil
}

func (w *ConcurrentWorkflow) Tag() string {
	return w.tag
}

func (w *ConcurrentWorkflow) Type() string {
	return PluginType
}

func (w *ConcurrentWorkflow) WithContext(ctx context.Context) {
	w.ctx = ctx
}

func (w *ConcurrentWorkflow) WithContextLogger(contextLogger log.ContextLogger) {
	w.logger = contextLogger
}

func (w *ConcurrentWorkflow) WithCore(core adapter.ExecPluginCore) {
	w.core = core
}

type respMsg struct {
	id     string
	dnsCtx *adapter.DNSContext
}

func (w *ConcurrentWorkflow) Exec(ctx context.Context, args map[string]any, dnsCtx *adapter.DNSContext) bool {
	var (
		workflowTags []string
		waitTime     time.Duration
	)
	if workflowsAny, ok := args["workflows"]; ok {
		workflowAnys, ok := workflowsAny.([]any)
		if !ok {
			w.logger.ErrorContext(ctx, fmt.Sprintf("workflows not found in args"))
			return false
		}
		workflowTags = make([]string, 0)
		for _, wa := range workflowAnys {
			workflowStr, ok := wa.(string)
			if !ok {
				w.logger.ErrorContext(ctx, fmt.Sprintf("workflows not found in args"))
				return false
			}
			workflowTags = append(workflowTags, workflowStr)
		}
		if len(workflowTags) == 0 {
			w.logger.ErrorContext(ctx, fmt.Sprintf("workflows not found in args"))
			return false
		}
		if len(workflowTags) == 2 {
			waitTimeAny, ok := args["wait-time"]
			if ok {
				waitTimeStr, ok := waitTimeAny.(string)
				if ok {
					wt, err := time.ParseDuration(waitTimeStr)
					if err != nil {
						w.logger.ErrorContext(ctx, fmt.Sprintf("parse wait-time fail: %s", err))
						return false
					}
					waitTime = wt
				}
			}
		}
	} else {
		w.logger.ErrorContext(ctx, fmt.Sprintf("workflows not found in args"))
		return false
	}
	var workflows []adapter.Workflow
	for _, workflowTag := range workflowTags {
		workflow := w.core.GetWorkflow(workflowTag)
		if workflow == nil {
			w.logger.ErrorContext(ctx, fmt.Sprintf("workflow %s not found", workflowTag))
			return false
		}
		workflows = append(workflows, workflow)
	}
	w.logger.DebugContext(ctx, "concurrent-workflow start")
	defer w.logger.DebugContext(ctx, "concurrent-workflow end")
	respChan := make(chan *respMsg, 1)
	var respDNSCtx *respMsg
	runCtx, runCancel := context.WithCancel(ctx)
	wg := sync.WaitGroup{}
	for index, workflow := range workflows {
		itemDNSCtx := dnsCtx.Clone()
		wg.Add(1)
		go func(runCtx context.Context, workflow adapter.Workflow, dnsCtx *adapter.DNSContext, index int) {
			defer wg.Done()
			if index == 1 && waitTime > 0 {
				w.logger.DebugContext(ctx, fmt.Sprintf("concurrent-workflow wait time start, wait %s", waitTime.String()))
				select {
				case <-runCtx.Done():
					return
				case <-time.After(waitTime):
					w.logger.DebugContext(ctx, "concurrent-workflow wait time end")
				}
			}
			runCtx = log.AddContextTag(runCtx)
			ctxTag := log.GetContextTag(runCtx)
			w.logger.DebugContext(ctx, fmt.Sprintf("workflow [%s] start, id: %s", workflow.Tag(), ctxTag))
			workflow.Exec(runCtx, dnsCtx)
			select {
			case <-runCtx.Done():
				return
			default:
			}
			if dnsCtx.RespMsg != nil {
				select {
				case respChan <- &respMsg{
					id:     ctxTag,
					dnsCtx: dnsCtx,
				}:
				default:
				}
			}
		}(runCtx, workflow, itemDNSCtx, index)
	}
	go func() {
		wg.Wait()
		runCancel()
	}()
	select {
	case <-runCtx.Done():
	case <-ctx.Done():
		runCancel()
		wg.Wait()
		return false
	case dnsMsg := <-respChan:
		respDNSCtx = dnsMsg
	}
	runCancel()
	go func() {
		wg.Wait()
		close(respChan)
	}()
	if respDNSCtx != nil {
		w.logger.DebugContext(ctx, fmt.Sprintf("has resp-msg, use id [%s]", respDNSCtx.id))
		respDNSCtx.dnsCtx.SaveTo(dnsCtx)
	}
	return true
}
