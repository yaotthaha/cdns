package option

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yaotthaha/cdns/lib/tools"
	"github.com/yaotthaha/cdns/option/execPlugin"
	"github.com/yaotthaha/cdns/option/listener"
	"github.com/yaotthaha/cdns/option/matchPlugin"
	"github.com/yaotthaha/cdns/option/upstream"
	"github.com/yaotthaha/cdns/option/workflow"

	"gopkg.in/yaml.v3"
)

type Option struct {
	LogOptions         LogOptions                       `config:"log"`
	APIOptions         APIOptions                       `config:"api"`
	UpstreamOptions    []upstream.UpstreamOptions       `config:"upstreams"`
	MatchPluginOptions []matchPlugin.MatchPluginOptions `config:"match-plugins"`
	ExecPluginOptions  []execPlugin.ExecPluginOptions   `config:"exec-plugins"`
	WorkflowOptions    []workflow.WorkflowOptions       `config:"workflows"`
	ListenerOptions    []listener.ListenerOptions       `config:"listeners"`
}

type configType string

const (
	JSON configType = "json"
	YAML configType = "yaml"
)

func ReadFile(file string) (*Option, error) {
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	switch filepath.Ext(file) {
	case ".json", ".jsonc":
		return ReadContent(content, JSON)
	case ".yaml", ".yml":
		return ReadContent(content, YAML)
	default:
		return ReadContent(content, YAML)
	}
}

func ReadContent(content []byte, configType configType) (*Option, error) {
	var optionMap map[string]any
	var err error
	switch configType {
	case JSON:
		err = json.Unmarshal(content, &optionMap)
	case YAML:
		err = yaml.Unmarshal(content, &optionMap)
	default:
		err = yaml.Unmarshal(content, &optionMap)
		if err != nil {
			err = json.Unmarshal(content, &optionMap)
			if err != nil {
				return nil, fmt.Errorf("config type %s not support", configType)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	var option Option
	err = tools.NewMapStructureDecoderWithResult(&option).Decode(optionMap)
	if err != nil {
		return nil, err
	}
	return &option, nil
}
