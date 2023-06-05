package upstream

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/yaotthaha/cdns/lib/types"
)

type UpstreamUDPOption struct {
	Address     netip.AddrPort     `yaml:"address"`
	IdleTimeout types.TimeDuration `yaml:"idle_timeout,omitempty"`
}

type _UpstreamUDPOption struct {
	Address     string             `yaml:"address"`
	IdleTimeout types.TimeDuration `yaml:"idle_timeout,omitempty"`
}

func (u *UpstreamUDPOption) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var upstreamUDPOption _UpstreamUDPOption
	err := unmarshal(&upstreamUDPOption)
	if err != nil {
		return err
	}
	addressStr := upstreamUDPOption.Address
	if addressStr == "" {
		return fmt.Errorf("upstream: udp: address is required")
	}
	ip, err := netip.ParseAddr(addressStr)
	if err == nil {
		addressStr = net.JoinHostPort(ip.String(), "53")
	}
	address, err := netip.ParseAddrPort(addressStr)
	if err != nil {
		return fmt.Errorf("upstream: udp: address: %s", err)
	}
	u.Address = address
	u.IdleTimeout = upstreamUDPOption.IdleTimeout
	return nil
}

func (u *UpstreamUDPOption) MarshalYAML() (interface{}, error) {
	return &_UpstreamUDPOption{
		Address:     u.Address.String(),
		IdleTimeout: u.IdleTimeout,
	}, nil
}
