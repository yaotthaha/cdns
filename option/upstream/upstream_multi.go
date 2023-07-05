package upstream

import "github.com/yaotthaha/cdns/lib/types"

type UpstreamMultiOptions struct {
	Upstreams    []string           `yaml:"upstreams"`
	QueryTimeout types.TimeDuration `yaml:"query-timeout,omitempty"`
}
