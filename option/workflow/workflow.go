package workflow

import (
	"fmt"
	"reflect"

	"github.com/mitchellh/mapstructure"
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
	var workflowOption _WorkflowOption
	err := mapstructure.Decode(from.Interface(), &workflowOption)
	if err != nil {
		return err
	}
	w.Tag = workflowOption.Tag
	if workflowOption.Rules != nil && len(workflowOption.Rules) > 0 {
		w.Rules = make([]any, len(workflowOption.Rules))
		for i, v := range workflowOption.Rules {
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
			err = mapstructure.Decode(v, r)
			if err != nil {
				return err
			}
			w.Rules[i] = r
		}
	}
	return nil
}
