package option

import (
	"github.com/yaotthaha/cdns/option/execPlugin"
	"github.com/yaotthaha/cdns/option/listener"
	"github.com/yaotthaha/cdns/option/matchPlugin"
	"github.com/yaotthaha/cdns/option/upstream"
	"github.com/yaotthaha/cdns/option/workflow"
)

type Option struct {
	LogOption          LogOption                       `yaml:"log"`
	APIOption          APIOption                       `yaml:"api"`
	UpstreamOptions    []upstream.UpstreamOption       `yaml:"upstreams"`
	MatchPluginOptions []matchPlugin.MatchPluginOption `yaml:"match_plugins"`
	ExecPluginOptions  []execPlugin.ExecPluginOption   `yaml:"exec_plugins"`
	WorkflowOptions    []workflow.WorkflowOption       `yaml:"workflows"`
	ListenerOptions    []listener.ListenerOptions      `yaml:"listeners"`
}
