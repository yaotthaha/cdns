package listener

import "github.com/yaotthaha/cdns/lib/types"

type ListenHTTPOptions struct {
	Listen       string                 `yaml:"listen"`
	Path         string                 `yaml:"path,inline"`
	ReadIPHeader types.Listable[string] `yaml:"read-ip-header,omitempty"`
	TrustIP      types.Listable[string] `yaml:"trust-ip,omitempty"`
	EnableH3     bool                   `yaml:"enable-h3,omitempty"`
	TLSOptions   *TLSOptions            `yaml:",inline"`
}
