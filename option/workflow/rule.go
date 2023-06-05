package workflow

import (
	"fmt"

	"github.com/yaotthaha/cdns/lib/types"

	"github.com/miekg/dns"
)

type DNSQType uint16

func (d *DNSQType) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var v any
	err := unmarshal(&v)
	if err != nil {
		return err
	}
	switch value := v.(type) {
	case string:
		qType, loaded := dns.StringToType[value]
		if loaded {
			*d = DNSQType(qType)
			return nil
		}
		return fmt.Errorf("unknown qtype: %s", value)
	case int:
		*d = DNSQType(value)
		return nil
	default:
		return fmt.Errorf("unknown qtype: %s", value)
	}
}

type RuleMatchOr struct {
	MatchOr types.Listable[RuleMatchItem] `yaml:"match_or"`
	Exec    types.Listable[RuleExecItem]  `yaml:"exec"`
}

func (r *RuleMatchOr) IsRule() {
}

type RuleMatchAnd struct {
	MatchAnd types.Listable[RuleMatchItem] `yaml:"match_and"`
	Exec     types.Listable[RuleExecItem]  `yaml:"exec"`
}

func (r *RuleMatchAnd) IsRule() {
}

type RuleExec struct {
	Exec types.Listable[RuleExecItem] `yaml:"exec"`
}

func (r *RuleExec) IsRule() {
}

type RuleMatchItem struct {
	ClientIP   types.Listable[*types.Addr] `yaml:"client_ip,omitempty"`
	QType      types.Listable[DNSQType]    `yaml:"qtype,omitempty"`
	QName      types.Listable[string]      `yaml:"qname,omitempty"`
	HasRespMsg *bool                       `yaml:"has_resp_msg,omitempty"`
	RespIP     types.Listable[*types.Addr] `yaml:"resp_ip,omitempty"` // A/AAAA
	Mark       types.Listable[uint64]      `yaml:"mark,omitempty"`
	Plugin     *RuleMatchPluginOption      `yaml:"plugin,omitempty"`
	//
	MatchOr  types.Listable[RuleMatchItem] `yaml:"match_or,omitempty"`
	MatchAnd types.Listable[RuleMatchItem] `yaml:"match_and,omitempty"`
	//
	Invert bool `yaml:"invert,omitempty"`
}

type _RuleMatchItem RuleMatchItem

func (r *RuleMatchItem) UnmarshalYAML(unmarshal func(interface{}) error) error {
	err := unmarshal((*_RuleMatchItem)(r))
	if err != nil {
		return err
	}
	var s int
	if r.ClientIP != nil && len(r.ClientIP) > 0 {
		s++
	}
	if r.QType != nil && len(r.QType) > 0 {
		s++
	}
	if r.QName != nil && len(r.QName) > 0 {
		s++
	}
	if r.HasRespMsg != nil {
		s++
	}
	if r.RespIP != nil && len(r.RespIP) > 0 {
		s++
	}
	if r.Mark != nil && len(r.Mark) > 0 {
		s++
	}
	if r.Plugin != nil {
		s++
	}
	if r.MatchOr != nil && len(r.MatchOr) > 0 {
		s++
	}
	if r.MatchAnd != nil && len(r.MatchAnd) > 0 {
		s++
	}
	if s == 0 {
		return fmt.Errorf("at least one match item is required")
	}
	if s > 1 {
		return fmt.Errorf("only one match item is allowed")
	}
	return nil
}

type RuleExecItem struct {
	Mark     *uint64                 `yaml:"mark,omitempty"`
	Plugin   *RuleExecPluginOption   `yaml:"plugin,omitempty"`
	Upstream *string                 `yaml:"upstream,omitempty"`
	JumpTo   *types.Listable[string] `yaml:"jump_to,omitempty"`
	GoTo     *string                 `yaml:"go_to,omitempty"`
	Return   any                     `yaml:"return,omitempty"`
}

type _RuleExecItem RuleExecItem

func (r *RuleExecItem) UnmarshalYAML(unmarshal func(interface{}) error) error {
	err := unmarshal((*_RuleExecItem)(r))
	if err != nil {
		return err
	}
	var s int
	if r.Mark != nil {
		s++
	}
	if r.Plugin != nil {
		s++
	}
	if r.Upstream != nil {
		s++
	}
	if r.JumpTo != nil && len(*r.JumpTo) > 0 {
		s++
	}
	if r.GoTo != nil {
		s++
	}
	if r.Return != nil {
		s++
	}
	if s == 0 {
		return fmt.Errorf("at least one exec item is required")
	}
	if s > 1 {
		return fmt.Errorf("only one exec item is allowed")
	}
	return nil
}
