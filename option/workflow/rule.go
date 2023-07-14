package workflow

import (
	"fmt"
	"reflect"

	"github.com/yaotthaha/cdns/lib/types"

	"github.com/mitchellh/mapstructure"
)

type RuleMatchOr struct {
	MatchOr  types.Listable[RuleMatchItem] `config:"match-or"`
	ElseExec types.Listable[RuleExecItem]  `config:"else-exec"`
	Exec     types.Listable[RuleExecItem]  `config:"exec"`
}

type RuleMatchAnd struct {
	MatchAnd types.Listable[RuleMatchItem] `config:"match-and"`
	ElseExec types.Listable[RuleExecItem]  `config:"else-exec"`
	Exec     types.Listable[RuleExecItem]  `config:"exec"`
}

type RuleExec struct {
	Exec types.Listable[RuleExecItem] `config:"exec"`
}

type RuleMatchItem struct {
	Listener   types.Listable[string]         `config:"listener,omitempty"`
	ClientIP   types.Listable[string]         `config:"client-ip,omitempty"`
	QType      types.Listable[types.DNSQType] `config:"qtype,omitempty"`
	QName      types.Listable[string]         `config:"qname,omitempty"`
	HasRespMsg *bool                          `config:"has-resp-msg,omitempty"`
	RespIP     types.Listable[string]         `config:"resp-ip,omitempty"`
	Mark       types.Listable[uint64]         `config:"mark,omitempty"`
	Env        map[string]string              `config:"env,omitempty"`
	Metadata   map[string]string              `config:"metadata,omitempty"`
	Plugin     *RuleMatchPluginOption         `config:"plugin,omitempty"`
	//
	MatchOr  types.Listable[RuleMatchItem] `config:"match-or,omitempty"`
	MatchAnd types.Listable[RuleMatchItem] `config:"match-and,omitempty"`
	//
	Invert bool `config:"invert,omitempty"`
}

type RuleExecItem struct {
	Mark     *uint64                 `config:"mark,omitempty"`
	Metadata map[string]string       `config:"metadata,omitempty"`
	Plugin   *RuleExecPluginOption   `config:"plugin,omitempty"`
	Upstream *string                 `config:"upstream,omitempty"`
	JumpTo   *types.Listable[string] `config:"jump-to,omitempty"`
	GoTo     *string                 `config:"go-to,omitempty"`
	SetTTL   *uint32                 `config:"set-ttl,omitempty"`
	Clean    *bool                   `config:"clean,omitempty"`
	Return   any                     `config:"return,omitempty"`
}

type _RuleExecItem RuleExecItem

func (r *RuleExecItem) Unmarshal(from reflect.Value) error {
	var stringOperate string
	err := mapstructure.Decode(from.Interface(), &stringOperate)
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
	err = mapstructure.Decode(from.Interface(), (*_RuleExecItem)(r))
	return err
}
