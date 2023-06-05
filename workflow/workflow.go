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

func NewWorkflow(core adapter.Core, logger log.Logger, options workflow.WorkflowOption) (*Workflow, error) {
	w := &Workflow{
		tag:    options.Tag,
		core:   core,
		logger: log.NewContextLogger(log.NewTagLogger(logger, fmt.Sprintf("workflow/%s", options.Tag))),
	}
	w.rules = make([]*Rule, 0)
	for _, r := range options.Rules {
		ru, err := newRule(core, r)
		if err != nil {
			return nil, err
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
			return false
		}
	}
	return true
}
