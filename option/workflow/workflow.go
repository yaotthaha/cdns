package workflow

import (
	"fmt"
	"reflect"

	"github.com/yaotthaha/cdns/lib/tools"
)

type _WorkflowOption struct {
	Tag   string           `config:"tag"`
	Rules []map[string]any `config:"rules"`
}

type WorkflowOptions struct {
	Tag   string `config:"tag"`
	Rules []any  `config:"rules"`
}

func (w *WorkflowOptions) Unmarshal(from reflect.Value) error {
	var _workflowOption _WorkflowOption
	err := tools.NewMapStructureDecoderWithResult(&_workflowOption).Decode(from.Interface())
	if err != nil {
		return err
	}
	w.Tag = _workflowOption.Tag
	if _workflowOption.Rules != nil && len(_workflowOption.Rules) > 0 {
		w.Rules = make([]any, len(_workflowOption.Rules))
		for i, v := range _workflowOption.Rules {
			var (
				haveMatchOr  bool
				haveMatchAnd bool
				haveElseExec bool
				haveExec     bool
			)
			for k := range v {
				switch {
				case k == "match-or":
					haveMatchOr = true
				case k == "match-and":
					haveMatchAnd = true
				case k == "else-exec":
					haveElseExec = true
				case k == "exec":
					haveExec = true
				}
			}
			var r any
			switch {
			case haveMatchOr && (haveElseExec || haveExec):
				r = &RuleMatchOr{}
			case haveMatchAnd && (haveElseExec || haveExec):
				r = &RuleMatchAnd{}
			case haveExec:
				r = &RuleExec{}
			default:
				return fmt.Errorf("invalid workflow rules: %+v", v)
			}
			err = tools.NewMapStructureDecoderWithResult(r).Decode(v)
			if err != nil {
				return err
			}
			w.Rules[i] = r
		}
	}
	return nil
}
