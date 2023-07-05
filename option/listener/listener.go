package listener

import (
	"fmt"

	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/lib/types"
)

type ListenerOptions struct {
	Tag      string `yaml:"tag"`
	Type     string `yaml:"type"`
	Options  any    `yaml:"options"`
	Workflow string `yaml:"workflow"`
}

type GetOptions interface {
	GetOptions() any
}

type ListenerTypeOptions[T any] struct {
	Tag     string `yaml:"tag"`
	Type    string `yaml:"type"`
	Options *T     `yaml:"options"`
}

func (l *ListenerTypeOptions[T]) GetOptions() any {
	return l.Options
}

type _ListenerOptions ListenerOptions

func (l *ListenerOptions) UnmarshalYAML(unmarshal func(interface{}) error) error {
	err := unmarshal((*_ListenerOptions)(l))
	if err != nil {
		return err
	}
	if l.Tag == "" {
		return fmt.Errorf("listener tag is required")
	}
	var opts GetOptions
	switch l.Type {
	case constant.ListenerUDP:
		opts = &ListenerTypeOptions[ListenerUDPOptions]{}
	case constant.ListenerTCP:
		opts = &ListenerTypeOptions[ListenerTCPOptions]{}
	case constant.ListenerTLS:
		opts = &ListenerTypeOptions[ListenerTLSOptions]{}
	case constant.ListenerHTTP:
		opts = &ListenerTypeOptions[ListenHTTPOptions]{}
	default:
		return fmt.Errorf("listener type %s is not supported", l.Type)
	}
	err = unmarshal(opts)
	if err != nil {
		return err
	}
	l.Options = opts.GetOptions()
	return nil
}

type TLSOptions struct {
	CertFile     string                 `yaml:"cert-file,omitempty"`
	KeyFile      string                 `yaml:"key-file,inline"`
	ClientCAFile types.Listable[string] `yaml:"client-ca-file,omitempty"`
}
