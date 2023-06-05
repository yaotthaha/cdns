package upstream

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"

	"github.com/yaotthaha/cdns/lib/types"
)

type UpstreamHTTPSOption struct {
	Address            netip.AddrPort     `yaml:"address"`
	IdleTimeout        types.TimeDuration `yaml:"idle_timeout,omitempty"`
	URL                *types.URL         `yaml:"url"`
	Header             map[string]string  `yaml:"header"`
	UseH3              bool               `yaml:"use_h3,omitempty"`
	InsecureSkipVerify bool               `yaml:"insecure_skip_verify,omitempty"`
	ServerName         string             `yaml:"server_name"`
	CAFile             string             `yaml:"ca_file,omitempty"`
	ClientCertFile     string             `yaml:"client_cert_file,omitempty"`
	ClientKeyFile      string             `yaml:"client_key_file,omitempty"`
}

type _UpstreamHTTPSOption struct {
	Address            string             `yaml:"address"`
	IdleTimeout        types.TimeDuration `yaml:"idle_timeout,omitempty"`
	URL                string             `yaml:"url"`
	Header             map[string]string  `yaml:"header"`
	UseH3              bool               `yaml:"use_h3,omitempty"`
	InsecureSkipVerify bool               `yaml:"insecure_skip_verify,omitempty"`
	ServerName         string             `yaml:"server_name"`
	CAFile             string             `yaml:"ca_file,omitempty"`
	ClientCertFile     string             `yaml:"client_cert_file,omitempty"`
	ClientKeyFile      string             `yaml:"client_key_file,omitempty"`
}

func (u *UpstreamHTTPSOption) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var upstreamHTTPSOption _UpstreamHTTPSOption
	err := unmarshal(&upstreamHTTPSOption)
	if err != nil {
		return err
	}
	url2, err := url.Parse(upstreamHTTPSOption.URL)
	if err != nil {
		return fmt.Errorf("upstream: https: url: %s", err)
	}
	u.URL = (*types.URL)(url2)
	addressStr := upstreamHTTPSOption.Address
	if addressStr == "" {
		addressStr = url2.Host
	}
	ip, err := netip.ParseAddr(addressStr)
	if err == nil {
		addressStr = net.JoinHostPort(ip.String(), "853")
	}
	address, err := netip.ParseAddrPort(addressStr)
	if err != nil {
		return fmt.Errorf("upstream: https: address: %s", err)
	}
	u.Address = address
	u.IdleTimeout = upstreamHTTPSOption.IdleTimeout
	u.Header = upstreamHTTPSOption.Header
	u.UseH3 = upstreamHTTPSOption.UseH3
	u.InsecureSkipVerify = upstreamHTTPSOption.InsecureSkipVerify
	u.ServerName = upstreamHTTPSOption.ServerName
	u.CAFile = upstreamHTTPSOption.CAFile
	u.ClientCertFile = upstreamHTTPSOption.ClientCertFile
	u.ClientKeyFile = upstreamHTTPSOption.ClientKeyFile
	return nil
}

func (u *UpstreamHTTPSOption) MarshalYAML() (interface{}, error) {
	return &_UpstreamHTTPSOption{
		Address:            u.Address.String(),
		IdleTimeout:        u.IdleTimeout,
		URL:                (*url.URL)(u.URL).String(),
		Header:             u.Header,
		UseH3:              u.UseH3,
		InsecureSkipVerify: u.InsecureSkipVerify,
		ServerName:         u.ServerName,
		CAFile:             u.CAFile,
		ClientCertFile:     u.ClientCertFile,
		ClientKeyFile:      u.ClientKeyFile,
	}, nil
}
