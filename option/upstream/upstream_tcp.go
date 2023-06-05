package upstream

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/yaotthaha/cdns/lib/types"
)

type UpstreamTCPOption struct {
	Address     netip.AddrPort     `yaml:"address"`
	IdleTimeout types.TimeDuration `yaml:"idle_timeout,omitempty"`
}

type _UpstreamTCPOption struct {
	Address     string             `yaml:"address"`
	IdleTimeout types.TimeDuration `yaml:"idle_timeout,omitempty"`
}

func (u *UpstreamTCPOption) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var upstreamTCPOption _UpstreamTCPOption
	err := unmarshal(&upstreamTCPOption)
	if err != nil {
		return err
	}
	addressStr := upstreamTCPOption.Address
	if addressStr == "" {
		return fmt.Errorf("upstream: tcp: address is required")
	}
	ip, err := netip.ParseAddr(addressStr)
	if err == nil {
		addressStr = net.JoinHostPort(ip.String(), "53")
	}
	address, err := netip.ParseAddrPort(addressStr)
	if err != nil {
		return fmt.Errorf("upstream: tcp: address: %s", err)
	}
	u.Address = address
	u.IdleTimeout = upstreamTCPOption.IdleTimeout
	return nil
}

func (u *UpstreamTCPOption) MarshalYAML() (interface{}, error) {
	return &_UpstreamTCPOption{
		Address:     u.Address.String(),
		IdleTimeout: u.IdleTimeout,
	}, nil
}
