package workflow

import (
	"context"
	"fmt"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/workflow"
)

type Workflow struct {
	tag    string
	core   adapter.Core
	logger log.ContextLogger
	rules  []*Rule
}

func NewWorkflow(core adapter.Core, logger log.ContextLogger, options workflow.WorkflowOptions) (*Workflow, error) {
	w := &Workflow{
		tag:    options.Tag,
		core:   core,
		logger: logger,
	}
	if options.Rules == nil || len(options.Rules) == 0 {
		return nil, fmt.Errorf("workflow has no rules")
	}
	w.rules = make([]*Rule, 0)
	for _, rule := range options.Rules {
		ru, err := newRule(core, rule)
		if err != nil {
			return nil, fmt.Errorf("init workflow rules fail: %s", err)
		}
		w.rules = append(w.rules, ru)
	}
	return w, nil
}

func (w *Workflow) Tag() string {
	return w.tag
}

func (w *Workflow) Exec(ctx context.Context, dnsCtx *adapter.DNSContext) constant.ReturnMode {
	dnsCtx.UsedWorkflow.Append(w)
	for _, r := range w.rules {
		returnMode := r.Exec(ctx, w.logger, dnsCtx)
		switch returnMode {
		case constant.ReturnOnce:
			w.logger.DebugContext(ctx, fmt.Sprintf("workflow %s return", w.tag))
			return constant.Continue
		case constant.ReturnAll:
			w.logger.DebugContext(ctx, fmt.Sprintf("workflow all return"))
			return constant.ReturnAll
		case constant.Continue:
		}
	}
	w.logger.DebugContext(ctx, fmt.Sprintf("workflow %s return", w.tag))
	return constant.Continue
}
