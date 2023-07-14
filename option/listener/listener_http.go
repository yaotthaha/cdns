package listener

import "github.com/yaotthaha/cdns/lib/types"

type ListenerHTTPOptions struct {
	Listen       string                 `config:"listen"`
	Path         string                 `config:"path,inline"`
	ReadIPHeader types.Listable[string] `config:"read-ip-header,omitempty"`
	TrustIP      types.Listable[string] `config:"trust-ip,omitempty"`
	EnableH3     bool                   `config:"enable-h3,omitempty"`
	TLSOptions   TLSOptions             `config:",squash"`
}
