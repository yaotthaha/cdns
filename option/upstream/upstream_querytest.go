package upstream

import "github.com/yaotthaha/cdns/lib/types"

type UpstreamQueryTestOption struct {
	Upstreams    []string           `yaml:"upstreams"`
	TestDomain   string             `yaml:"test_domain"`
	TestInterval types.TimeDuration `yaml:"test_interval"`
	Fallback     bool               `yaml:"fallback"`
}
