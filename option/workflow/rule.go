package workflow

import (
	"github.com/yaotthaha/cdns/lib/types"
)

type RuleMatchOr struct {
	MatchOr types.Listable[RuleMatchItem] `yaml:"match_or"`
	Exec    types.Listable[RuleExecItem]  `yaml:"exec"`
}

type RuleMatchAnd struct {
	MatchAnd types.Listable[RuleMatchItem] `yaml:"match_and"`
	Exec     types.Listable[RuleExecItem]  `yaml:"exec"`
}

type RuleExec struct {
	Exec types.Listable[RuleExecItem] `yaml:"exec"`
}

type RuleMatchItem struct {
	Listener   types.Listable[string]         `yaml:"listener,omitempty"`
	ClientIP   types.Listable[string]         `yaml:"client_ip,omitempty"`
	QType      types.Listable[types.DNSQType] `yaml:"qtype,omitempty"`
	QName      types.Listable[string]         `yaml:"qname,omitempty"`
	HasRespMsg *bool                          `yaml:"has_resp_msg,omitempty"`
	RespIP     types.Listable[string]         `yaml:"resp_ip,omitempty"`
	Mark       types.Listable[uint64]         `yaml:"mark,omitempty"`
	Plugin     *RuleMatchPluginOption         `yaml:"plugin,omitempty"`
	//
	MatchOr  types.Listable[RuleMatchItem] `yaml:"match_or,omitempty"`
	MatchAnd types.Listable[RuleMatchItem] `yaml:"match_and,omitempty"`
	//
	Invert bool `yaml:"invert,omitempty"`
}

type RuleExecItem struct {
	Mark     *uint64                 `yaml:"mark,omitempty"`
	Plugin   *RuleExecPluginOption   `yaml:"plugin,omitempty"`
	Upstream *string                 `yaml:"upstream,omitempty"`
	JumpTo   *types.Listable[string] `yaml:"jump_to,omitempty"`
	GoTo     *string                 `yaml:"go_to,omitempty"`
	Return   any                     `yaml:"return,omitempty"`
}
