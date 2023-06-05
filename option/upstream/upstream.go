package upstream

import (
	"fmt"
	"net/netip"

	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/lib/types"
)

type UpstreamOption struct {
	Tag          string               `yaml:"tag"`
	Type         string               `yaml:"type"`
	DialerOption UpstreamDialerOption `yaml:"dialer,omitempty"`
	UDPOption    UpstreamUDPOption    `yaml:"udp,omitempty"`
	TCPOption    UpstreamTCPOption    `yaml:"tcp,omitempty"`
	TLSOption    UpstreamTLSOption    `yaml:"tls,omitempty"`
	HTTPSOption  UpstreamHTTPSOption  `yaml:"https,omitempty"`
	QUICOption   UpstreamQUICOption   `yaml:"quic,omitempty"`
	RandomOption UpstreamRandomOption `yaml:"random,omitempty"`
	MultiOption  UpstreamMultiOption  `yaml:"multi,omitempty"`
}

type _UpstreamOption UpstreamOption

func (u *UpstreamOption) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var upstreamOption _UpstreamOption
	err := unmarshal(&upstreamOption)
	if err != nil {
		return err
	}
	if upstreamOption.Tag == "" {
		return fmt.Errorf("upstream: tag is required")
	}
	switch upstreamOption.Type {
	case constant.UpstreamUDP:
		u.UDPOption = upstreamOption.UDPOption
	case constant.UpstreamTCP:
		u.TCPOption = upstreamOption.TCPOption
	case constant.UpstreamTLS:
		u.TLSOption = upstreamOption.TLSOption
	case constant.UpstreamHTTPS:
		u.HTTPSOption = upstreamOption.HTTPSOption
	case constant.UpstreamQUIC:
		u.QUICOption = upstreamOption.QUICOption
	case constant.UpstreamRandom:
		u.RandomOption = upstreamOption.RandomOption
	case constant.UpstreamMulti:
		u.MultiOption = upstreamOption.MultiOption
	default:
		return fmt.Errorf("upstream: unknown type: %s", upstreamOption.Type)
	}
	*u = UpstreamOption(upstreamOption)
	return nil
}

type UpstreamDialerOption struct {
	Timeout        types.TimeDuration `yaml:"timeout,omitempty"`
	SoMark         uint32             `yaml:"so_mark,omitempty"`
	BindInterface  string             `yaml:"bind_interface,omitempty"`
	BindIP         netip.Addr         `yaml:"bind_ip,omitempty"`
	Socks5Address  netip.AddrPort     `yaml:"socks5_address,omitempty"`
	Socks5Username string             `yaml:"socks5_username,omitempty"`
	Socks5Password string             `yaml:"socks5_password,omitempty"`
}

type _UpstreamDialerOption struct {
	Timeout        types.TimeDuration `yaml:"timeout,omitempty"`
	SoMark         uint32             `yaml:"so_mark,omitempty"`
	BindInterface  string             `yaml:"bind_interface,omitempty"`
	BindIP         string             `yaml:"bind_ip,omitempty"`
	Socks5Address  string             `yaml:"socks5_address,omitempty"`
	Socks5Username string             `yaml:"socks5_username,omitempty"`
	Socks5Password string             `yaml:"socks5_password,omitempty"`
}

func (u *UpstreamDialerOption) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var upstreamDialerOption _UpstreamDialerOption
	err := unmarshal(&upstreamDialerOption)
	if err != nil {
		return err
	}
	u.Timeout = upstreamDialerOption.Timeout
	u.SoMark = upstreamDialerOption.SoMark
	u.BindInterface = upstreamDialerOption.BindInterface
	if upstreamDialerOption.BindIP != "" {
		bindIP, err := netip.ParseAddr(upstreamDialerOption.BindIP)
		if err != nil {
			return fmt.Errorf("upstream: invalid bind_ip: %s", upstreamDialerOption.BindIP)
		}
		u.BindIP = bindIP
	}
	if upstreamDialerOption.Socks5Address != "" {
		socks5Addr, err := netip.ParseAddrPort(upstreamDialerOption.Socks5Address)
		if err != nil {
			return fmt.Errorf("upstream: invalid socks5_address: %s", upstreamDialerOption.Socks5Address)
		}
		u.Socks5Address = socks5Addr
		u.Socks5Username = upstreamDialerOption.Socks5Username
		u.Socks5Password = upstreamDialerOption.Socks5Password
	}
	return nil
}

func (u *UpstreamDialerOption) MarshalYAML() (interface{}, error) {
	return &_UpstreamDialerOption{
		Timeout:        u.Timeout,
		SoMark:         u.SoMark,
		BindInterface:  u.BindInterface,
		BindIP:         u.BindIP.String(),
		Socks5Address:  u.Socks5Address.String(),
		Socks5Username: u.Socks5Username,
		Socks5Password: u.Socks5Password,
	}, nil
}
