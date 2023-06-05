package upstream

import (
	"fmt"
	"net"
	"net/netip"
)

type UpstreamQUICOption struct {
	Address            netip.AddrPort `yaml:"address"`
	InsecureSkipVerify bool           `yaml:"insecure_skip_verify,omitempty"`
	ServerName         string         `yaml:"server_name"`
	CAFile             string         `yaml:"ca_file,omitempty"`
	ClientCertFile     string         `yaml:"client_cert_file,omitempty"`
	ClientKeyFile      string         `yaml:"client_key_file,omitempty"`
}

type _UpstreamQUICOption struct {
	Address            string `yaml:"address"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify,omitempty"`
	ServerName         string `yaml:"server_name"`
	CAFile             string `yaml:"ca_file,omitempty"`
	ClientCertFile     string `yaml:"client_cert_file,omitempty"`
	ClientKeyFile      string `yaml:"client_key_file,omitempty"`
}

func (u *UpstreamQUICOption) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var upstreamQUICOption _UpstreamQUICOption
	err := unmarshal(&upstreamQUICOption)
	if err != nil {
		return err
	}
	addressStr := upstreamQUICOption.Address
	if addressStr == "" {
		return fmt.Errorf("upstream: quic: address is required")
	}
	ip, err := netip.ParseAddr(addressStr)
	if err == nil {
		addressStr = net.JoinHostPort(ip.String(), "784")
	}
	address, err := netip.ParseAddrPort(addressStr)
	if err != nil {
		return fmt.Errorf("upstream: quic: address: %s", err)
	}
	u.Address = address
	u.InsecureSkipVerify = upstreamQUICOption.InsecureSkipVerify
	u.ServerName = upstreamQUICOption.ServerName
	u.CAFile = upstreamQUICOption.CAFile
	u.ClientCertFile = upstreamQUICOption.ClientCertFile
	u.ClientKeyFile = upstreamQUICOption.ClientKeyFile
	return nil
}

func (u *UpstreamQUICOption) MarshalYAML() (interface{}, error) {
	return &_UpstreamQUICOption{
		Address:            u.Address.String(),
		InsecureSkipVerify: u.InsecureSkipVerify,
		ServerName:         u.ServerName,
		CAFile:             u.CAFile,
		ClientCertFile:     u.ClientCertFile,
		ClientKeyFile:      u.ClientKeyFile,
	}, nil
}
