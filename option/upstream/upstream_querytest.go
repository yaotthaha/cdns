package upstream

import "github.com/yaotthaha/cdns/lib/types"

type UpstreamQueryTestOptions struct {
	Upstreams    []string           `config:"upstreams"`
	QueryTimeout types.TimeDuration `config:"query-timeout,omitempty"`
	TestDomain   string             `config:"test-domain"`
	TestInterval types.TimeDuration `config:"test-interval"`
	Fallback     bool               `config:"fallback"`
}
