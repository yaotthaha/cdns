package upstream

import (
	"fmt"

	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/lib/types"
)

type UpstreamOptions struct {
	Tag     string `yaml:"tag"`
	Type    string `yaml:"type"`
	Options any    `yaml:"options"`
}

type _UpstreamOptions UpstreamOptions

type GetOptions interface {
	GetOptions() any
}

type UpstreamTypeOptions[T any] struct {
	Tag     string `yaml:"tag"`
	Type    string `yaml:"type"`
	Options *T     `yaml:"options"`
}

func (u *UpstreamTypeOptions[T]) GetOptions() any {
	return u.Options
}

func (u *UpstreamOptions) UnmarshalYAML(unmarshal func(interface{}) error) error {
	err := unmarshal((*_UpstreamOptions)(u))
	if err != nil {
		return err
	}
	if u.Tag == "" {
		return fmt.Errorf("upstream tag is empty")
	}
	var opts GetOptions
	switch u.Type {
	case constant.UpstreamUDP:
		opts = &UpstreamTypeOptions[UpstreamUDPOptions]{}
	case constant.UpstreamTCP:
		opts = &UpstreamTypeOptions[UpstreamTCPOptions]{}
	case constant.UpstreamTLS:
		opts = &UpstreamTypeOptions[UpstreamTLSOptions]{}
	case constant.UpstreamHTTPS:
		opts = &UpstreamTypeOptions[UpstreamHTTPSOptions]{}
	case constant.UpstreamQUIC:
		opts = &UpstreamTypeOptions[UpstreamQUICOptions]{}
	case constant.UpstreamMulti:
		opts = &UpstreamTypeOptions[UpstreamMultiOptions]{}
	case constant.UpstreamRandom:
		opts = &UpstreamTypeOptions[UpstreamRandomOptions]{}
	case constant.UpstreamQueryTest:
		opts = &UpstreamTypeOptions[UpstreamQueryTestOptions]{}
	default:
		return fmt.Errorf("upstream type %s is not supported", u.Type)
	}
	err = unmarshal(opts)
	if err != nil {
		return err
	}
	u.Options = opts.GetOptions()
	return nil
}

type DialerOptions struct {
	Timeout       types.TimeDuration `yaml:"timeout,omitempty"`
	SoMark        uint32             `yaml:"so-mark,omitempty"`
	BindInterface string             `yaml:"bind-interface,omitempty"`
	BindIP        string             `yaml:"bind-ip,omitempty"`
	Socks5        *Socks5Options     `yaml:"socks5,omitempty"`
}

type Socks5Options struct {
	Address  string `yaml:"address"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
}

type BootstrapOptions struct {
	Upstream string `yaml:"upstream"`
	Strategy string `yaml:"strategy,omitempty"`
}

type TLSOptions struct {
	ServerName         string                 `yaml:"servername,omitempty"`
	InsecureSkipVerify bool                   `yaml:"insecure-skip-verify,omitempty"`
	CAFile             types.Listable[string] `yaml:"ca-file,omitempty"`
	ClientCertFile     string                 `yaml:"client-cert-file,omitempty"`
	ClientKeyFile      string                 `yaml:"client-key-file,omitempty"`
}
