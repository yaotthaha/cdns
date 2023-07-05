package upstream

import (
	"github.com/yaotthaha/cdns/lib/types"
)

type UpstreamTLSOptions struct {
	Address        string `yaml:"address"`
	TLSOptions     `yaml:",inline"`
	ConnectTimeout types.TimeDuration `yaml:"connect-timeout,omitempty"`
	QueryTimeout   types.TimeDuration `yaml:"query-timeout,omitempty"`
	IdleTimeout    types.TimeDuration `yaml:"idle-timeout,omitempty"`
	Dialer         DialerOptions      `yaml:"dialer,omitempty"`
	Bootstrap      *BootstrapOptions  `yaml:"bootstrap,omitempty"`
}
