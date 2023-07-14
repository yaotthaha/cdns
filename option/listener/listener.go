package listener

import (
	"fmt"
	"reflect"

	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/lib/types"

	"github.com/mitchellh/mapstructure"
)

type ListenerOptions struct {
	Tag      string `config:"tag"`
	Type     string `config:"type"`
	Workflow string `config:"workflow"`
	//
	UDPOptions  *ListenerUDPOptions
	TCPOptions  *ListenerTCPOptions
	TLSOptions  *ListenerTLSOptions
	HTTPOptions *ListenerHTTPOptions
}

type _ListenerOptions struct {
	Tag      string         `config:"tag"`
	Type     string         `config:"type"`
	Options  map[string]any `config:"options"`
	Workflow string         `config:"workflow"`
}

func (l *ListenerOptions) Unmarshal(from reflect.Value) error {
	var _listenerOptions _ListenerOptions
	err := mapstructure.Decode(from.Interface(), &_listenerOptions)
	if err != nil {
		return err
	}
	if _listenerOptions.Tag == "" {
		return fmt.Errorf("listener tag is required")
	} else {
		l.Tag = _listenerOptions.Tag
	}
	if _listenerOptions.Workflow == "" {
		return fmt.Errorf("listener workflow is required")
	} else {
		l.Workflow = _listenerOptions.Workflow
	}
	decoderConfig := &mapstructure.DecoderConfig{
		DecodeHook: mapstructure.UnmarshalInterfaceHookFunc(),
		TagName:    "config",
	}
	l.Type = _listenerOptions.Type
	switch l.Type {
	case constant.ListenerUDP:
		l.UDPOptions = &ListenerUDPOptions{}
		decoderConfig.Result = l.UDPOptions
	case constant.ListenerTCP:
		l.TCPOptions = &ListenerTCPOptions{}
		decoderConfig.Result = l.TCPOptions
	case constant.ListenerTLS:
		l.TLSOptions = &ListenerTLSOptions{}
		decoderConfig.Result = l.TLSOptions
	case constant.ListenerHTTP:
		l.HTTPOptions = &ListenerHTTPOptions{}
		decoderConfig.Result = l.HTTPOptions
	default:
		return fmt.Errorf("listener type %s is not supported", l.Type)
	}
	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return err
	}
	err = decoder.Decode(_listenerOptions.Options)
	if err != nil {
		return err
	}
	return nil
}

type TLSOptions struct {
	CertFile     string                 `config:"cert-file,omitempty"`
	KeyFile      string                 `config:"key-file,inline"`
	ClientCAFile types.Listable[string] `config:"client-ca-file,omitempty"`
}
