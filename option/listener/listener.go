package listener

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/yaotthaha/cdns/constant"
)

type ListenerOptions struct {
	Tag        string             `yaml:"tag"`
	Type       string             `yaml:"type"`
	Listen     netip.AddrPort     `yaml:"listen"`
	Workflow   string             `yaml:"workflow"`
	UDPOptions ListenerUDPOptions `yaml:"udp,omitempty"`
	TCPOptions ListenerTCPOptions `yaml:"tcp,omitempty"`
}

type _ListenerOptions struct {
	Tag        string             `yaml:"tag"`
	Type       string             `yaml:"type"`
	Listen     string             `yaml:"listen"`
	Workflow   string             `yaml:"workflow"`
	UDPOptions ListenerUDPOptions `yaml:"udp,omitempty"`
	TCPOptions ListenerTCPOptions `yaml:"tcp,omitempty"`
}

func (l *ListenerOptions) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var listenerOptions _ListenerOptions
	err := unmarshal(&listenerOptions)
	if err != nil {
		return err
	}
	if listenerOptions.Tag == "" {
		return fmt.Errorf("listener: tag is required")
	}
	l.Tag = listenerOptions.Tag
	l.Type = listenerOptions.Type
	switch listenerOptions.Type {
	case constant.ListenerUDP:
		l.UDPOptions = listenerOptions.UDPOptions
	case constant.ListenerTCP:
		l.TCPOptions = listenerOptions.TCPOptions
	default:
		return fmt.Errorf("listener: unknown type: %s", listenerOptions.Type)
	}
	if listenerOptions.Listen == "" {
		return fmt.Errorf("listener: listen is required")
	}
	host, port, err := net.SplitHostPort(listenerOptions.Listen)
	if err != nil {
		return err
	}
	if host == "" {
		host = "::"
	}
	addrPort, err := netip.ParseAddrPort(net.JoinHostPort(host, port))
	if err != nil {
		return err
	}
	if !addrPort.IsValid() {
		return fmt.Errorf("listener: invalid listen address: %s", listenerOptions.Listen)
	}
	l.Listen = addrPort
	l.Workflow = listenerOptions.Workflow
	return nil
}

func (l ListenerOptions) MarshalYAML() (interface{}, error) {
	var listenerOptions _ListenerOptions
	listenerOptions.Tag = l.Tag
	listenerOptions.Type = l.Type
	listenerOptions.Listen = l.Listen.String()
	listenerOptions.Workflow = l.Workflow
	switch l.Type {
	case constant.ListenerUDP:
		listenerOptions.UDPOptions = l.UDPOptions
	case constant.ListenerTCP:
		listenerOptions.TCPOptions = l.TCPOptions
	default:
		return nil, fmt.Errorf("listener: unknown type: %s", l.Type)
	}
	return listenerOptions, nil
}
