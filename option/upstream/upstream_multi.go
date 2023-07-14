package upstream

import "github.com/yaotthaha/cdns/lib/types"

type UpstreamMultiOptions struct {
	Upstreams    []string           `config:"upstreams"`
	QueryTimeout types.TimeDuration `config:"query-timeout,omitempty"`
}
