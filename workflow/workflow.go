package workflow

import (
	"context"
	"fmt"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/workflow"
)

type Workflow struct {
	tag    string
	core   adapter.Core
	logger log.ContextLogger
	rules  []*Rule
}

func NewWorkflow(core adapter.Core, logger log.Logger, options workflow.WorkflowOptions) (*Workflow, error) {
	w := &Workflow{
		tag:    options.Tag,
		core:   core,
		logger: log.NewContextLogger(log.NewTagLogger(logger, fmt.Sprintf("workflow/%s", options.Tag))),
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

func (w *Workflow) Exec(ctx context.Context, dnsCtx *adapter.DNSContext) bool {
	dnsCtx.WithWorkflow(w)
	for _, r := range w.rules {
		if !r.Exec(ctx, w.logger, dnsCtx) {
			w.logger.DebugContext(ctx, fmt.Sprintf("workflow %s return", w.tag))
			return false
		}
	}
	w.logger.DebugContext(ctx, fmt.Sprintf("workflow %s return", w.tag))
	return true
}
