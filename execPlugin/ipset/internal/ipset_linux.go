//go:build linux

package internal

import (
	"errors"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
)

var _ IPSet = (*IPSetLinux)(nil)

type IPSetLinux struct {
	name    string
	typ     InetType
	handler *netlink.Handle
}

var ErrInetMismatch = errors.New("ipset: address family mismatch")

func New(name string, typ InetType, timeout time.Duration) (*IPSetLinux, error) {
	handler, err := netlink.NewHandle()
	if err != nil {
		return nil, err
	}
	createOptions := netlink.IpsetCreateOptions{
		Replace:  true,
		Skbinfo:  true,
		Revision: 1,
	}
	createOptions.Timeout = new(uint32)
	if timeout <= 0 {
		*createOptions.Timeout = 0
	} else {
		*createOptions.Timeout = uint32(timeout.Seconds())
	}
	err = handler.IpsetCreate(name, "hash:net", createOptions)
	if err != nil {
		return nil, err
	}
	return &IPSetLinux{
		name:    name,
		typ:     typ,
		handler: handler,
	}, nil
}

func (i *IPSetLinux) Name() string {
	return i.name
}

func (i *IPSetLinux) Close() error {
	i.handler.IpsetDestroy(i.name)
	i.handler.Close()
	return nil
}

func (i *IPSetLinux) AddIP(addr netip.Addr, ttl time.Duration) error {
	if addr.Is4() && i.typ == Inet6 {
		return ErrInetMismatch
	}
	if addr.Is6() && i.typ == Inet4 {
		return ErrInetMismatch
	}
	e := &netlink.IPSetEntry{
		Replace: true,
		IP:      addr.AsSlice(),
	}
	ttlUint32 := uint32(ttl.Seconds())
	if ttl > 0 {
		e.Timeout = &ttlUint32
	}
	return i.handler.IpsetAdd(i.name, e)
}

func (i *IPSetLinux) AddCIDR(addr netip.Prefix, ttl time.Duration) error {
	if addr.Addr().Is4() && i.typ == Inet6 {
		return ErrInetMismatch
	}
	if addr.Addr().Is6() && i.typ == Inet4 {
		return ErrInetMismatch
	}
	e := &netlink.IPSetEntry{
		Replace: true,
		IP:      addr.Addr().AsSlice(),
		CIDR:    uint8(addr.Bits()),
	}
	ttlUint32 := uint32(ttl.Seconds())
	if ttl > 0 {
		e.Timeout = &ttlUint32
	}
	return i.handler.IpsetAdd(i.name, e)
}

func (i *IPSetLinux) DelIP(addr netip.Addr) error {
	if addr.Is4() && i.typ == Inet6 {
		return ErrInetMismatch
	}
	if addr.Is6() && i.typ == Inet4 {
		return ErrInetMismatch
	}
	e := &netlink.IPSetEntry{
		IP: addr.AsSlice(),
	}
	return i.handler.IpsetDel(i.name, e)
}

func (i *IPSetLinux) DelCIDR(addr netip.Prefix) error {
	if addr.Addr().Is4() && i.typ == Inet6 {
		return ErrInetMismatch
	}
	if addr.Addr().Is6() && i.typ == Inet4 {
		return ErrInetMismatch
	}
	e := &netlink.IPSetEntry{
		IP:   addr.Addr().AsSlice(),
		CIDR: uint8(addr.Bits()),
	}
	return i.handler.IpsetDel(i.name, e)
}

func (i *IPSetLinux) FlushAll() error {
	return i.handler.IpsetFlush(i.name)
}
