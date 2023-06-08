package listener

import "github.com/yaotthaha/cdns/lib/types"

type ListenHTTPOptions struct {
	Path         string                 `yaml:"path"`
	ReadIPHeader types.Listable[string] `yaml:"read_ip_header"`
	TrustIP      types.Listable[string] `yaml:"trust_ip"`
	UseH3        bool                   `yaml:"use_h3"`
	TLSOptions   *ListenHTTPTLSOptions  `yaml:",inline"`
}

type ListenHTTPTLSOptions struct {
	CertFile     string `yaml:"cert_file"`
	KeyFile      string `yaml:"key_file"`
	ClientCAFile string `yaml:"client_ca_file"`
}
