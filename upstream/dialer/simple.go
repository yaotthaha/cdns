package dialer

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/option/upstream"
	"github.com/yaotthaha/cdns/upstream/dialer/control"
)

var _ NetDialer = (*simpleDialer)(nil)

type simpleDialer struct {
	tcp4Dialer *net.Dialer
	tcp6Dialer *net.Dialer
	udp4Dialer *net.Dialer
	udp6Dialer *net.Dialer
}

func newSimpleDialer(options upstream.DialerOptions) (*simpleDialer, error) {
	tcp4Dialer := &net.Dialer{}
	tcp6Dialer := &net.Dialer{}
	udp4Dialer := &net.Dialer{}
	udp6Dialer := &net.Dialer{}
	if options.Timeout > 0 {
		tcp4Dialer.Timeout = time.Duration(options.Timeout)
		tcp6Dialer.Timeout = time.Duration(options.Timeout)
	} else {
		tcp4Dialer.Timeout = constant.TCPDialTimeout
		tcp6Dialer.Timeout = constant.TCPDialTimeout
	}
	if options.SoMark > 0 {
		tcp4Dialer.Control = control.SetMark(options.SoMark)
		tcp6Dialer.Control = control.SetMark(options.SoMark)
		udp4Dialer.Control = control.SetMark(options.SoMark)
		udp6Dialer.Control = control.SetMark(options.SoMark)
	}
	if options.BindInterface != "" {
		netInterface, err := net.InterfaceByName(options.BindInterface)
		if err != nil {
			return nil, fmt.Errorf("failed to get interface %s: %v", options.BindInterface, err)
		}
		if tcp4Dialer.Control == nil {
			tcp4Dialer.Control = func(network string, address string, c syscall.RawConn) error {
				return control.BindToInterface(c, "4", netInterface.Name, netInterface.Index)
			}
		} else {
			tcp4Dialer.Control = control.AppendControl(tcp4Dialer.Control, func(network string, address string, c syscall.RawConn) error {
				return control.BindToInterface(c, "4", netInterface.Name, netInterface.Index)
			})
		}
		if tcp6Dialer.Control == nil {
			tcp6Dialer.Control = func(network string, address string, c syscall.RawConn) error {
				return control.BindToInterface(c, "6", netInterface.Name, netInterface.Index)
			}
		} else {
			tcp6Dialer.Control = control.AppendControl(tcp6Dialer.Control, func(network string, address string, c syscall.RawConn) error {
				return control.BindToInterface(c, "6", netInterface.Name, netInterface.Index)
			})
		}
		if udp4Dialer.Control == nil {
			udp4Dialer.Control = func(network string, address string, c syscall.RawConn) error {
				return control.BindToInterface(c, "4", netInterface.Name, netInterface.Index)
			}
		} else {
			udp4Dialer.Control = control.AppendControl(udp4Dialer.Control, func(network string, address string, c syscall.RawConn) error {
				return control.BindToInterface(c, "4", netInterface.Name, netInterface.Index)
			})
		}
		if udp6Dialer.Control == nil {
			udp6Dialer.Control = func(network string, address string, c syscall.RawConn) error {
				return control.BindToInterface(c, "6", netInterface.Name, netInterface.Index)
			}
		} else {
			udp6Dialer.Control = control.AppendControl(udp6Dialer.Control, func(network string, address string, c syscall.RawConn) error {
				return control.BindToInterface(c, "6", netInterface.Name, netInterface.Index)
			})
		}
	}
	if options.BindIP != "" {
		bindIP, err := netip.ParseAddr(options.BindIP)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bind-ip %s: %v", options.BindIP, err)
		}
		tcp4Dialer.LocalAddr = &net.TCPAddr{
			IP: bindIP.AsSlice(),
		}
		tcp6Dialer.LocalAddr = &net.TCPAddr{
			IP: bindIP.AsSlice(),
		}
		udp4Dialer.LocalAddr = &net.UDPAddr{
			IP: bindIP.AsSlice(),
		}
		udp6Dialer.LocalAddr = &net.UDPAddr{
			IP: bindIP.AsSlice(),
		}
	}
	d := &simpleDialer{
		tcp4Dialer: tcp4Dialer,
		tcp6Dialer: tcp6Dialer,
		udp4Dialer: udp4Dialer,
		udp6Dialer: udp6Dialer,
	}
	return d, nil
}

func (d *simpleDialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	switch network {
	case "tcp":
		network = "tcp4"
		ip, err := netip.ParseAddrPort(address)
		if err == nil {
			if ip.Addr().Is4() {
				network = "tcp4"
			} else {
				network = "tcp6"
			}
		}
		fallthrough
	case "tcp4":
		return d.tcp4Dialer.DialContext(ctx, network, address)
	case "tcp6":
		return d.tcp6Dialer.DialContext(ctx, network, address)
	case "udp":
		network = "udp4"
		ip, err := netip.ParseAddrPort(address)
		if err == nil {
			if ip.Addr().Is4() {
				network = "udp4"
			} else {
				network = "udp6"
			}
		}
		fallthrough
	case "udp4":
		return d.udp4Dialer.DialContext(ctx, network, address)
	case "udp6":
		return d.udp6Dialer.DialContext(ctx, network, address)
	}
	return nil, fmt.Errorf("unsupported network %s", network)
}

func (d *simpleDialer) DialParallel(ctx context.Context, network string, addresses []string) (net.Conn, error) {
	return dialParallel(ctx, d, network, addresses)
}
