package upstream

import (
	"github.com/yaotthaha/cdns/lib/types"
)

type UpstreamHTTPSOptions struct {
	Address        string `config:"address"`
	TLSOptions     `config:",squash"`
	ConnectTimeout types.TimeDuration `config:"connect-timeout,omitempty"`
	IdleTimeout    types.TimeDuration `config:"idle-timeout,omitempty"`
	QueryTimeout   types.TimeDuration `config:"query-timeout,omitempty"`
	Path           string             `config:"path"`
	Header         map[string]string  `config:"header,omitempty"`
	EnableH3       bool               `config:"enable-h3,omitempty"`
	Dialer         DialerOptions      `config:"dialer,omitempty"`
	Bootstrap      *BootstrapOptions  `config:"bootstrap,omitempty"`
}
