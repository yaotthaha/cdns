package upstream

import (
	"github.com/yaotthaha/cdns/lib/types"
)

type UpstreamTCPOption struct {
	Address     string             `yaml:"address"`
	IdleTimeout types.TimeDuration `yaml:"idle_timeout,omitempty"`
}
