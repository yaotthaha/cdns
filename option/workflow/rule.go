package workflow

import (
	"fmt"

	"github.com/yaotthaha/cdns/lib/types"
)

type RuleMatchOr struct {
	MatchOr  types.Listable[RuleMatchItem] `yaml:"match-or"`
	ElseExec types.Listable[RuleExecItem]  `yaml:"else-exec"`
	Exec     types.Listable[RuleExecItem]  `yaml:"exec"`
}

type RuleMatchAnd struct {
	MatchAnd types.Listable[RuleMatchItem] `yaml:"match-and"`
	ElseExec types.Listable[RuleExecItem]  `yaml:"else-exec"`
	Exec     types.Listable[RuleExecItem]  `yaml:"exec"`
}

type RuleExec struct {
	Exec types.Listable[RuleExecItem] `yaml:"exec"`
}

type RuleMatchItem struct {
	Listener   types.Listable[string]         `yaml:"listener,omitempty"`
	ClientIP   types.Listable[string]         `yaml:"client-ip,omitempty"`
	QType      types.Listable[types.DNSQType] `yaml:"qtype,omitempty"`
	QName      types.Listable[string]         `yaml:"qname,omitempty"`
	HasRespMsg *bool                          `yaml:"has-resp-msg,omitempty"`
	RespIP     types.Listable[string]         `yaml:"resp-ip,omitempty"`
	Mark       types.Listable[uint64]         `yaml:"mark,omitempty"`
	Plugin     *RuleMatchPluginOption         `yaml:"plugin,omitempty"`
	//
	MatchOr  types.Listable[RuleMatchItem] `yaml:"match-or,omitempty"`
	MatchAnd types.Listable[RuleMatchItem] `yaml:"match-and,omitempty"`
	//
	Invert bool `yaml:"invert,omitempty"`
}

type RuleExecItem struct {
	Mark     *uint64                 `yaml:"mark,omitempty"`
	Plugin   *RuleExecPluginOption   `yaml:"plugin,omitempty"`
	Upstream *string                 `yaml:"upstream,omitempty"`
	JumpTo   *types.Listable[string] `yaml:"jump-to,omitempty"`
	GoTo     *string                 `yaml:"go-to,omitempty"`
	SetTTL   *uint32                 `yaml:"set-ttl,omitempty"`
	Clean    *bool                   `yaml:"clean,omitempty"`
	Return   any                     `yaml:"return,omitempty"`
}

type _RuleExecItem RuleExecItem

func (r *RuleExecItem) UnmarshalYAML(unmarshal func(any) error) error {
	var stringOperate string
	err := unmarshal(&stringOperate)
	if err == nil {
		switch stringOperate {
		case "return":
			r.Return = true
		case "clean":
			r.Clean = new(bool)
			*r.Clean = true
		default:
			return fmt.Errorf("invalid rule exec item: %s", stringOperate)
		}
		return nil
	}
	err = unmarshal((*_RuleExecItem)(r))
	return err
}
