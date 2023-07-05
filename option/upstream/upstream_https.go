package upstream

import (
	"github.com/yaotthaha/cdns/lib/types"
)

type UpstreamHTTPSOptions struct {
	Address        string `yaml:"address"`
	TLSOptions     `yaml:",inline"`
	ConnectTimeout types.TimeDuration `yaml:"connect-timeout,omitempty"`
	IdleTimeout    types.TimeDuration `yaml:"idle-timeout,omitempty"`
	QueryTimeout   types.TimeDuration `yaml:"query-timeout,omitempty"`
	Path           string             `yaml:"path"`
	Header         map[string]string  `yaml:"header,omitempty"`
	EnableH3       bool               `yaml:"enable-h3,omitempty"`
	Dialer         DialerOptions      `yaml:"dialer,omitempty"`
	Bootstrap      *BootstrapOptions  `yaml:"bootstrap,omitempty"`
}
