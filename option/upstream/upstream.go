package upstream

import (
	"github.com/yaotthaha/cdns/lib/types"
)

type UpstreamOption struct {
	Tag             string                  `yaml:"tag"`
	Type            string                  `yaml:"type"`
	DialerOption    UpstreamDialerOption    `yaml:"dialer,omitempty"`
	UDPOption       UpstreamUDPOption       `yaml:"udp,omitempty"`
	TCPOption       UpstreamTCPOption       `yaml:"tcp,omitempty"`
	TLSOption       UpstreamTLSOption       `yaml:"tls,omitempty"`
	HTTPSOption     UpstreamHTTPSOption     `yaml:"https,omitempty"`
	QUICOption      UpstreamQUICOption      `yaml:"quic,omitempty"`
	RandomOption    UpstreamRandomOption    `yaml:"random,omitempty"`
	MultiOption     UpstreamMultiOption     `yaml:"multi,omitempty"`
	QueryTestOption UpstreamQueryTestOption `yaml:"querytest,omitempty"`
}

type UpstreamDialerOption struct {
	Timeout        types.TimeDuration `yaml:"timeout,omitempty"`
	SoMark         uint32             `yaml:"so_mark,omitempty"`
	BindInterface  string             `yaml:"bind_interface,omitempty"`
	BindIP         string             `yaml:"bind_ip,omitempty"`
	Socks5Address  *string            `yaml:"socks5_address,omitempty"`
	Socks5Username string             `yaml:"socks5_username,omitempty"`
	Socks5Password string             `yaml:"socks5_password,omitempty"`
}
