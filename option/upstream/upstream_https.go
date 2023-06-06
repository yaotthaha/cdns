package upstream

import (
	"github.com/yaotthaha/cdns/lib/types"
)

type UpstreamHTTPSOption struct {
	Address            string             `yaml:"address"`
	IdleTimeout        types.TimeDuration `yaml:"idle_timeout,omitempty"`
	URL                string             `yaml:"url"`
	Header             map[string]string  `yaml:"header,omitempty"`
	UseH3              bool               `yaml:"use_h3,omitempty"`
	InsecureSkipVerify bool               `yaml:"insecure_skip_verify,omitempty"`
	ServerName         string             `yaml:"server_name,omitempty"`
	CAFile             string             `yaml:"ca_file,omitempty"`
	ClientCertFile     string             `yaml:"client_cert_file,omitempty"`
	ClientKeyFile      string             `yaml:"client_key_file,omitempty"`
}
