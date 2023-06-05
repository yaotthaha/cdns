package upstream

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/yaotthaha/cdns/lib/types"
)

type UpstreamTLSOption struct {
	Address            netip.AddrPort     `yaml:"address"`
	InsecureSkipVerify bool               `yaml:"insecure_skip_verify,omitempty"`
	ServerName         string             `yaml:"server_name"`
	CAFile             string             `yaml:"ca_file,omitempty"`
	ClientCertFile     string             `yaml:"client_cert_file,omitempty"`
	ClientKeyFile      string             `yaml:"client_key_file,omitempty"`
	IdleTimeout        types.TimeDuration `yaml:"idle_timeout,omitempty"`
}

type _UpstreamTLSOption struct {
	Address            string             `yaml:"address"`
	InsecureSkipVerify bool               `yaml:"insecure_skip_verify,omitempty"`
	ServerName         string             `yaml:"server_name"`
	CAFile             string             `yaml:"ca_file,omitempty"`
	ClientCertFile     string             `yaml:"client_cert_file,omitempty"`
	ClientKeyFile      string             `yaml:"client_key_file,omitempty"`
	IdleTimeout        types.TimeDuration `yaml:"idle_timeout,omitempty"`
}

func (u *UpstreamTLSOption) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var upstreamTLSOption _UpstreamTLSOption
	err := unmarshal(&upstreamTLSOption)
	if err != nil {
		return err
	}
	addressStr := upstreamTLSOption.Address
	if addressStr == "" {
		return fmt.Errorf("upstream: tls: address is required")
	}
	ip, err := netip.ParseAddr(addressStr)
	if err == nil {
		addressStr = net.JoinHostPort(ip.String(), "853")
	}
	address, err := netip.ParseAddrPort(addressStr)
	if err != nil {
		return fmt.Errorf("upstream: tls: address: %s", err)
	}
	u.Address = address
	u.InsecureSkipVerify = upstreamTLSOption.InsecureSkipVerify
	u.ServerName = upstreamTLSOption.ServerName
	u.CAFile = upstreamTLSOption.CAFile
	u.ClientCertFile = upstreamTLSOption.ClientCertFile
	u.ClientKeyFile = upstreamTLSOption.ClientKeyFile
	u.IdleTimeout = upstreamTLSOption.IdleTimeout
	return nil
}

func (u *UpstreamTLSOption) MarshalYAML() (interface{}, error) {
	return &_UpstreamTLSOption{
		Address:            u.Address.String(),
		InsecureSkipVerify: u.InsecureSkipVerify,
		ServerName:         u.ServerName,
		CAFile:             u.CAFile,
		ClientCertFile:     u.ClientCertFile,
		ClientKeyFile:      u.ClientKeyFile,
		IdleTimeout:        u.IdleTimeout,
	}, nil
}
