package workflow_go

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/log"

	"gopkg.in/yaml.v3"
)

const PluginType = "workflow-go"

var _ adapter.ExecPlugin = (*WorkflowGo)(nil)

func init() {
	adapter.RegisterExecPlugin(PluginType, NewWorkflowGo)
}

type WorkflowGo struct {
	tag          string
	ctx          context.Context
	logger       log.ContextLogger
	core         adapter.ExecPluginCore
	workflowTags []string
	workflow     []adapter.Workflow
}

type option struct {
	Workflows []string `yaml:"workflows"`
}

func NewWorkflowGo(tag string, args map[string]any) (adapter.ExecPlugin, error) {
	w := &WorkflowGo{
		tag: tag,
	}
	optionBytes, err := yaml.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("parse args fail: %s", err)
	}
	var op option
	err = yaml.Unmarshal(optionBytes, &op)
	if err != nil {
		return nil, fmt.Errorf("parse args fail: %s", err)
	}
	if op.Workflows == nil || len(op.Workflows) < 1 {
		return nil, fmt.Errorf("workflows must be at least 1")
	}
	w.workflowTags = op.Workflows
	return w, nil
}

func (w *WorkflowGo) Tag() string {
	return w.tag
}

func (w *WorkflowGo) Type() string {
	return PluginType
}

func (w *WorkflowGo) Start() error {
	w.workflow = make([]adapter.Workflow, 0, len(w.workflowTags))
	for _, workflowTag := range w.workflowTags {
		workflow := w.core.GetWorkflow(workflowTag)
		if workflow == nil {
			return fmt.Errorf("workflow %s not found", workflowTag)
		}
		w.workflow = append(w.workflow, workflow)
	}
	return nil
}

func (w *WorkflowGo) Close() error {
	return nil
}

func (w *WorkflowGo) WithContext(ctx context.Context) {
	w.ctx = ctx
}

func (w *WorkflowGo) WithLogger(logger log.ContextLogger) {
	w.logger = logger
}

func (w *WorkflowGo) WithCore(core adapter.ExecPluginCore) {
	w.core = core
}

func (w *WorkflowGo) APIHandler() http.Handler {
	return nil
}

type respMsg struct {
	id     string
	dnsCtx *adapter.DNSContext
}

func (w *WorkflowGo) Exec(ctx context.Context, _ map[string]any, dnsCtx *adapter.DNSContext) bool {
	w.logger.DebugContext(ctx, "workflow-go start")
	defer w.logger.DebugContext(ctx, "workflow-go end")
	respChan := make(chan *respMsg, 1)
	var respDNSCtx *respMsg
	runCtx, runCancel := context.WithCancel(ctx)
	wg := sync.WaitGroup{}
	for _, workflow := range w.workflow {
		itemDNSCtx := dnsCtx.Clone()
		wg.Add(1)
		go func(runCtx context.Context, workflow adapter.Workflow, dnsCtx *adapter.DNSContext) {
			defer wg.Done()
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
		}(runCtx, workflow, itemDNSCtx)
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
		w.logger.DebugContext(ctx, fmt.Sprintf("has resp_msg, use id [%s]", respDNSCtx.id))
		respDNSCtx.dnsCtx.SaveTo(dnsCtx)
	}
	return true
}
