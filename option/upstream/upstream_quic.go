package upstream

import "github.com/yaotthaha/cdns/lib/types"

type UpstreamQUICOptions struct {
	Address        string `config:"address"`
	TLSOptions     `config:",squash"`
	ConnectTimeout types.TimeDuration `config:"connect-timeout,omitempty"`
	QueryTimeout   types.TimeDuration `config:"query-timeout,omitempty"`
	IdleTimeout    types.TimeDuration `config:"idle-timeout,omitempty"`
	Dialer         DialerOptions      `config:"dialer,omitempty"`
	Bootstrap      *BootstrapOptions  `config:"bootstrap,omitempty"`
}
