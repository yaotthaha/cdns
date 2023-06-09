package upstream

import (
	"github.com/yaotthaha/cdns/lib/types"
)

type UpstreamTCPOption struct {
	Address      string             `yaml:"address"`
	QueryTimeout types.TimeDuration `yaml:"query_timeout,omitempty"`
	IdleTimeout  types.TimeDuration `yaml:"idle_timeout,omitempty"`
}
