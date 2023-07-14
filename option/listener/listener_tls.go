package listener

import "github.com/yaotthaha/cdns/lib/types"

type ListenerTLSOptions struct {
	Listen      string             `config:"listen"`
	IdleTimeout types.TimeDuration `config:"idle-timeout,omitempty"`
	TLSOption   TLSOptions         `config:",squash"`
}
