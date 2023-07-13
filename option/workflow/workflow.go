package workflow

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

type _WorkflowOption struct {
	Tag   string           `yaml:"tag"`
	Rules []map[string]any `yaml:"rules"`
}

type WorkflowOptions struct {
	Tag   string `yaml:"tag"`
	Rules []any  `yaml:"rules"`
}

func (w *WorkflowOptions) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var workflowOption _WorkflowOption
	err := unmarshal(&workflowOption)
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
			ruleBytes, err := yaml.Marshal(v)
			if err != nil {
				return err
			}
			err = yaml.Unmarshal(ruleBytes, r)
			if err != nil {
				return err
			}
			w.Rules[i] = r
		}
	}
	return nil
}
