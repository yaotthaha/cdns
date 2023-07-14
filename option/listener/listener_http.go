package listener

import "github.com/yaotthaha/cdns/lib/types"

type ListenerHTTPOptions struct {
	Listen       string                 `config:"listen"`
	Path         string                 `config:"path,inline"`
	RealIPHeader types.Listable[string] `config:"real-ip-header,omitempty"`
	TrustIP      types.Listable[string] `config:"trust-ip,omitempty"`
	EnableH3     bool                   `config:"enable-h3,omitempty"`
	TLSOptions   TLSOptions             `config:",squash"`
}
