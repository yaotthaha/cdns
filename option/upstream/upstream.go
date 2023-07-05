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

type _initUpstreamOptions struct {
	Tag  string `yaml:"tag"`
	Type string `yaml:"type"`
}

func (u *UpstreamOptions) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var initOptions _initUpstreamOptions
	err := unmarshal(&initOptions)
	if err != nil {
		return err
	}
	if initOptions.Tag == "" {
		return fmt.Errorf("upstream tag is empty")
	}
	var opts any
	switch initOptions.Type {
	case constant.UpstreamUDP:
		opts = &UpstreamUDPOptions{}
	case constant.UpstreamTCP:
		opts = &UpstreamTCPOptions{}
	case constant.UpstreamTLS:
		opts = &UpstreamTLSOptions{}
	case constant.UpstreamHTTPS:
		opts = &UpstreamHTTPSOptions{}
	case constant.UpstreamQUIC:
		opts = &UpstreamQUICOptions{}
	case constant.UpstreamMulti:
		opts = &UpstreamMultiOptions{}
	case constant.UpstreamRandom:
		opts = &UpstreamRandomOptions{}
	case constant.UpstreamQueryTest:
		opts = &UpstreamQueryTestOptions{}
	default:
		return fmt.Errorf("upstream type %s is not supported", initOptions.Type)
	}
	u.Options = opts
	return unmarshal((*_UpstreamOptions)(u))
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
