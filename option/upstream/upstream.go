package upstream

import (
	"fmt"
	"reflect"

	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/lib/types"

	"github.com/mitchellh/mapstructure"
)

type UpstreamOptions struct {
	Tag  string `config:"tag"`
	Type string `config:"type"`
	//
	UDPOptions   *UpstreamUDPOptions
	TCPOptions   *UpstreamTCPOptions
	TLSOptions   *UpstreamTLSOptions
	HTTPSOptions *UpstreamHTTPSOptions
	QUICOptions  *UpstreamQUICOptions
	//
	MultiOptions     *UpstreamMultiOptions
	RandomOptions    *UpstreamRandomOptions
	QueryTestOptions *UpstreamQueryTestOptions
}

type _UpstreamOptions struct {
	Tag     string         `config:"tag"`
	Type    string         `config:"type"`
	Options map[string]any `config:"options"`
}

func (u *UpstreamOptions) Unmarshal(from reflect.Value) error {
	var _upstreamOptions _UpstreamOptions
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.UnmarshalInterfaceHookFunc(),
		Result:     &_upstreamOptions,
		TagName:    "config",
	})
	if err != nil {
		return err
	}
	err = decoder.Decode(from.Interface())
	if err != nil {
		return err
	}
	if _upstreamOptions.Tag == "" {
		return fmt.Errorf("upstream tag is empty")
	} else {
		u.Tag = _upstreamOptions.Tag
	}
	decoderConfig := &mapstructure.DecoderConfig{
		DecodeHook: mapstructure.UnmarshalInterfaceHookFunc(),
		TagName:    "config",
	}
	u.Type = _upstreamOptions.Type
	switch u.Type {
	case constant.UpstreamUDP:
		u.UDPOptions = &UpstreamUDPOptions{}
		decoderConfig.Result = u.UDPOptions
	case constant.UpstreamTCP:
		u.TCPOptions = &UpstreamTCPOptions{}
		decoderConfig.Result = u.TCPOptions
	case constant.UpstreamTLS:
		u.TLSOptions = &UpstreamTLSOptions{}
		decoderConfig.Result = u.TLSOptions
	case constant.UpstreamHTTPS:
		u.HTTPSOptions = &UpstreamHTTPSOptions{}
		decoderConfig.Result = u.HTTPSOptions
	case constant.UpstreamQUIC:
		u.QUICOptions = &UpstreamQUICOptions{}
		decoderConfig.Result = u.QUICOptions
	case constant.UpstreamMulti:
		u.MultiOptions = &UpstreamMultiOptions{}
		decoderConfig.Result = u.MultiOptions
	case constant.UpstreamRandom:
		u.RandomOptions = &UpstreamRandomOptions{}
		decoderConfig.Result = u.RandomOptions
	case constant.UpstreamQueryTest:
		u.QueryTestOptions = &UpstreamQueryTestOptions{}
		decoderConfig.Result = u.QueryTestOptions
	default:
		return fmt.Errorf("upstream type %s is not supported", u.Type)
	}
	decoder, err = mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return err
	}
	err = decoder.Decode(_upstreamOptions.Options)
	if err != nil {
		return err
	}
	return nil
}

type DialerOptions struct {
	Timeout       types.TimeDuration `config:"timeout,omitempty"`
	SoMark        uint32             `config:"so-mark,omitempty"`
	BindInterface string             `config:"bind-interface,omitempty"`
	BindIP        string             `config:"bind-ip,omitempty"`
	Socks5        *Socks5Options     `config:"socks5,omitempty"`
}

type Socks5Options struct {
	Address  string `config:"address"`
	Username string `config:"username,omitempty"`
	Password string `config:"password,omitempty"`
}

type BootstrapOptions struct {
	Upstream string `config:"upstream"`
	Strategy string `config:"strategy,omitempty"`
}

type TLSOptions struct {
	ServerName         string                 `config:"servername,omitempty"`
	InsecureSkipVerify bool                   `config:"insecure-skip-verify,omitempty"`
	CAFile             types.Listable[string] `config:"ca-file,omitempty"`
	ClientCertFile     string                 `config:"client-cert-file,omitempty"`
	ClientKeyFile      string                 `config:"client-key-file,omitempty"`
}
