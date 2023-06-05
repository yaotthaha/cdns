package workflow

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

type Rule interface {
	IsRule()
}

type _WorkflowOption struct {
	Tag   string           `yaml:"tag"`
	Rules []map[string]any `yaml:"rules"`
}

type WorkflowOption struct {
	Tag   string `yaml:"tag"`
	Rules []Rule `yaml:"rules"`
}

func (w *WorkflowOption) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var workflowOption _WorkflowOption
	err := unmarshal(&workflowOption)
	if err != nil {
		return err
	}
	if workflowOption.Tag == "" {
		return fmt.Errorf("tag must not be empty")
	}
	w.Tag = workflowOption.Tag
	if workflowOption.Rules == nil || len(workflowOption.Rules) == 0 {
		return fmt.Errorf("rules must not be empty")
	}
	w.Rules = make([]Rule, len(workflowOption.Rules))
	for i, v := range workflowOption.Rules {
		var (
			haveMatchOr  bool
			haveMatchAnd bool
			haveExec     bool
		)
		for k := range v {
			switch {
			case k == "match_or":
				haveMatchOr = true
			case k == "match_and":
				haveMatchAnd = true
			case k == "exec":
				haveExec = true
			}
		}
		var r Rule
		switch {
		case haveMatchOr && haveExec:
			r = &RuleMatchOr{}
		case haveMatchAnd && haveExec:
			r = &RuleMatchAnd{}
		case haveExec:
			r = &RuleExec{}
		default:
			return fmt.Errorf("workflow: %s, invalid rules: %+v", workflowOption.Tag, v)
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
	return nil
}
