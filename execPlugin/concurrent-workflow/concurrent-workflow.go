package concurrent_workflow

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
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

func (w *ConcurrentWorkflow) Exec(ctx context.Context, args map[string]any, dnsCtx *adapter.DNSContext) (constant.ReturnMode, error) {
	var (
		workflowTags []string
		waitTime     time.Duration
	)
	if workflowsAny, ok := args["workflows"]; ok {
		workflowAnys, ok := workflowsAny.([]any)
		if !ok {
			err := fmt.Errorf("workflows not found in args")
			w.logger.ErrorContext(ctx, err)
			return constant.ReturnAll, err
		}
		workflowTags = make([]string, 0)
		for _, wa := range workflowAnys {
			workflowStr, ok := wa.(string)
			if !ok {
				err := fmt.Errorf("workflows not found in args")
				w.logger.ErrorContext(ctx, err)
				return constant.ReturnAll, err
			}
			workflowTags = append(workflowTags, workflowStr)
		}
		if len(workflowTags) == 0 {
			err := fmt.Errorf("workflows not found in args")
			w.logger.ErrorContext(ctx, err)
			return constant.ReturnAll, err
		}
		if len(workflowTags) == 2 {
			waitTimeAny, ok := args["wait-time"]
			if ok {
				waitTimeStr, ok := waitTimeAny.(string)
				if ok {
					wt, err := time.ParseDuration(waitTimeStr)
					if err != nil {
						err = fmt.Errorf("parse wait-time fail: %s", err)
						w.logger.ErrorContext(ctx, err)
						return constant.ReturnAll, err
					}
					waitTime = wt
				}
			}
		}
	} else {
		err := fmt.Errorf("workflows not found in args")
		w.logger.ErrorContext(ctx, err)
		return constant.ReturnAll, err
	}
	var workflows []adapter.Workflow
	for _, workflowTag := range workflowTags {
		workflow := w.core.GetWorkflow(workflowTag)
		if workflow == nil {
			err := fmt.Errorf("workflow %s not found", workflowTag)
			w.logger.ErrorContext(ctx, err)
			return constant.ReturnAll, err
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
		itemDNSCtx := adapter.GetNewDNSContext()
		dnsCtx.SaveTo(itemDNSCtx)
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
					adapter.PutDNSContext(dnsCtx)
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
		return constant.ReturnAll, context.Canceled
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
		adapter.PutDNSContext(respDNSCtx.dnsCtx)
	}
	return constant.Continue, nil
}
