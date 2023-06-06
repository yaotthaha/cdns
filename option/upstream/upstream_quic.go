package upstream

type UpstreamQUICOption struct {
	Address            string `yaml:"address"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify,omitempty"`
	ServerName         string `yaml:"server_name,omitempty"`
	CAFile             string `yaml:"ca_file,omitempty"`
	ClientCertFile     string `yaml:"client_cert_file,omitempty"`
	ClientKeyFile      string `yaml:"client_key_file,omitempty"`
}
