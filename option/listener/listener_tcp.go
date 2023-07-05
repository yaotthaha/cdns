package listener

import "github.com/yaotthaha/cdns/lib/types"

type ListenerTCPOptions struct {
	Listen      string             `yaml:"listen"`
	IdleTimeout types.TimeDuration `yaml:"idle-timeout,omitempty"`
}
