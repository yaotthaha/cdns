package workflow

import (
	"context"
	"fmt"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/workflow"
)

const (
	modeAnd = "and"
	modeOr  = "or"
)

type Rule struct {
	core      adapter.Core
	mode      string
	matchers  []*matchItem
	elseExecs []*execItem
	execs     []*execItem
}

func newRule(core adapter.Core, options any) (*Rule, error) {
	r := &Rule{
		core: core,
	}
	switch options := options.(type) {
	case *workflow.RuleMatchOr:
		matchers := make([]*matchItem, 0)
		for _, mItem := range options.MatchOr {
			m, err := newMatchItem(core, mItem)
			if err != nil {
				return nil, fmt.Errorf("init matcher_or rule fail, module: match_or: %s", err)
			}
			matchers = append(matchers, m)
		}
		r.matchers = matchers
		ee := false
		if options.ElseExec != nil && len(options.ElseExec) > 0 {
			execs := make([]*execItem, 0)
			for _, eItem := range options.ElseExec {
				e, err := newExecItem(core, eItem)
				if err != nil {
					return nil, fmt.Errorf("init matcher_or rule fail, module: else_exec: %s", err)
				}
				execs = append(execs, e)
			}
			r.elseExecs = execs
			ee = true
		}
		if options.Exec != nil && len(options.Exec) > 0 {
			execs := make([]*execItem, 0)
			for _, eItem := range options.Exec {
				e, err := newExecItem(core, eItem)
				if err != nil {
					return nil, fmt.Errorf("init matcher_or rule fail, module: exec: %s", err)
				}
				execs = append(execs, e)
			}
			r.execs = execs
			ee = true
		}
		if !ee {
			return nil, fmt.Errorf("init matcher_or rule fail, module: no exec or else_exec")
		}
		r.mode = modeOr
	case *workflow.RuleMatchAnd:
		matchers := make([]*matchItem, 0)
		for _, mItem := range options.MatchAnd {
			m, err := newMatchItem(core, mItem)
			if err != nil {
				return nil, fmt.Errorf("init matcher_and rule fail, module: match_and: %s", err)
			}
			matchers = append(matchers, m)
		}
		r.matchers = matchers
		ee := false
		if options.ElseExec != nil && len(options.ElseExec) > 0 {
			execs := make([]*execItem, 0)
			for _, eItem := range options.ElseExec {
				e, err := newExecItem(core, eItem)
				if err != nil {
					return nil, fmt.Errorf("init matcher_and rule fail, module: else_exec: %s", err)
				}
				execs = append(execs, e)
			}
			r.elseExecs = execs
			ee = true
		}
		if options.Exec != nil && len(options.Exec) > 0 {
			execs := make([]*execItem, 0)
			for _, eItem := range options.Exec {
				e, err := newExecItem(core, eItem)
				if err != nil {
					return nil, fmt.Errorf("init matcher_and rule fail, module: exec: %s", err)
				}
				execs = append(execs, e)
			}
			r.execs = execs
			ee = true
		}
		if !ee {
			return nil, fmt.Errorf("init matcher_and rule fail, module: no exec or else_exec")
		}
		r.mode = modeAnd
	case *workflow.RuleExec:
		execs := make([]*execItem, 0)
		for _, eItem := range options.Exec {
			e, err := newExecItem(core, eItem)
			if err != nil {
				return nil, fmt.Errorf("init exec rule fail: %s", err)
			}
			execs = append(execs, e)
		}
		r.execs = execs
	default:
		return nil, fmt.Errorf("init rule fail: unknown rule type: %T", options)
	}
	return r, nil
}

func (r *Rule) match(ctx context.Context, logger log.ContextLogger, dnsCtx *adapter.DNSContext) int {
	if r.matchers != nil {
		orN := 0
		for _, matcher := range r.matchers {
			select {
			case <-ctx.Done():
				return -1
			default:
			}
			match := matcher.match(ctx, logger, dnsCtx)
			switch r.mode {
			case modeAnd:
				if match {
					continue
				} else {
					return 0
				}
			case modeOr:
				if match {
					orN++
					continue
				} else {
					continue
				}
			default:
				return 0
			}
		}
		switch r.mode {
		case modeAnd:
		case modeOr:
			if orN == 0 {
				return 0
			}
		}
		return 1
	}
	return 1
}

func (r *Rule) Exec(ctx context.Context, logger log.ContextLogger, dnsCtx *adapter.DNSContext) bool {
	m := r.match(ctx, logger, dnsCtx)
	if m == -1 {
		return false
	}
	if m == 0 {
		if r.elseExecs != nil {
			logger.DebugContext(ctx, fmt.Sprintf("rule no match, mode: %s, run else_exec", r.mode))
			for _, e := range r.elseExecs {
				select {
				case <-ctx.Done():
					return false
				default:
				}
				if !e.exec(ctx, logger, dnsCtx) {
					return false
				}
			}
			return true
		} else {
			logger.DebugContext(ctx, fmt.Sprintf("rule no match, mode: %s, else_exec has no rule, continue", r.mode))
			return true
		}
	}
	if m == 1 {
		if r.elseExecs != nil {
			logger.DebugContext(ctx, fmt.Sprintf("rule match success, mode: %s, run exec", r.mode))
			for _, e := range r.execs {
				select {
				case <-ctx.Done():
					return false
				default:
				}
				if !e.exec(ctx, logger, dnsCtx) {
					return false
				}
			}
			return true
		} else {
			logger.DebugContext(ctx, fmt.Sprintf("rule match success, mode: %s, exec has no rule, continue", r.mode))
			return true
		}
	}
	return false
}
