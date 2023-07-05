package upstream

import "github.com/yaotthaha/cdns/lib/types"

type UpstreamQueryTestOptions struct {
	Upstreams    []string           `yaml:"upstreams"`
	QueryTimeout types.TimeDuration `yaml:"query-timeout,omitempty"`
	TestDomain   string             `yaml:"test-domain"`
	TestInterval types.TimeDuration `yaml:"test-interval"`
	Fallback     bool               `yaml:"fallback"`
}
