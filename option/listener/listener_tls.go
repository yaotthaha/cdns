package listener

import "github.com/yaotthaha/cdns/lib/types"

type ListenerTLSOptions struct {
	Listen      string             `yaml:"listen"`
	IdleTimeout types.TimeDuration `yaml:"idle-timeout,omitempty"`
	TLSOption   TLSOptions         `yaml:",inline"`
}
