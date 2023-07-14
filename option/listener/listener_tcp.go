package listener

import "github.com/yaotthaha/cdns/lib/types"

type ListenerTCPOptions struct {
	Listen      string             `config:"listen"`
	IdleTimeout types.TimeDuration `config:"idle-timeout,omitempty"`
}
