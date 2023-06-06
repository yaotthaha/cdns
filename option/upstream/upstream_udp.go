package upstream

import (
	"github.com/yaotthaha/cdns/lib/types"
)

type UpstreamUDPOption struct {
	Address     string             `yaml:"address"`
	IdleTimeout types.TimeDuration `yaml:"idle_timeout,omitempty"`
}
