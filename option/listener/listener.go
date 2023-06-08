package listener

type ListenerOptions struct {
	Tag         string             `yaml:"tag"`
	Type        string             `yaml:"type"`
	Listen      string             `yaml:"listen"`
	Workflow    string             `yaml:"workflow"`
	UDPOptions  ListenerUDPOptions `yaml:"udp,omitempty"`
	TCPOptions  ListenerTCPOptions `yaml:"tcp,omitempty"`
	TLSOptions  ListenerTLSOptions `yaml:"tls,omitempty"`
	HTTPOptions ListenHTTPOptions  `yaml:"http,omitempty"`
}
