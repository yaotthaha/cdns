package option

import (
	"github.com/yaotthaha/cdns/option/execPlugin"
	"github.com/yaotthaha/cdns/option/listener"
	"github.com/yaotthaha/cdns/option/matchPlugin"
	"github.com/yaotthaha/cdns/option/upstream"
	"github.com/yaotthaha/cdns/option/workflow"
)

type Option struct {
	LogOptions         LogOptions                       `yaml:"log"`
	APIOptions         APIOptions                       `yaml:"api"`
	UpstreamOptions    []upstream.UpstreamOptions       `yaml:"upstreams"`
	MatchPluginOptions []matchPlugin.MatchPluginOptions `yaml:"match-plugins"`
	ExecPluginOptions  []execPlugin.ExecPluginOptions   `yaml:"exec-plugins"`
	WorkflowOptions    []workflow.WorkflowOptions       `yaml:"workflows"`
	ListenerOptions    []listener.ListenerOptions       `yaml:"listeners"`
}
