//go:build linux

package internal

import (
	"errors"
	"net/netip"
	"time"
)

type IPSetLinux struct {
	name string
	tye  InetType
	nl   *NetLink
}

var ErrInetMismatch = errors.New("ipset: address family mismatch")

func New(name string, typ InetType) (*IPSetLinux, error) {
	nl, err := NewNetLink()
	if err != nil {
		return nil, err
	}
	err = nl.CreateSet(name, func(opts *Options) {
		if typ == Inet6 {
			opts.IPv6 = true
		}
	})
	if err != nil {
		return nil, err
	}
	return &IPSetLinux{
		name: name,
		tye:  typ,
		nl:   nl,
	}, nil
}

func (i *IPSetLinux) Destroy() error {
	return i.nl.DestroySet(i.name)
}

func (i *IPSetLinux) AddIP(addr netip.Addr, ttl time.Duration) error {
	if addr.Is4() && i.tye == Inet6 {
		return ErrInetMismatch
	}
	if addr.Is6() && i.tye == Inet4 {
		return ErrInetMismatch
	}
	return i.nl.HandleAddr(IPSET_CMD_ADD, i.name, addr, netip.Prefix{}, func(opts *Options) {
		if ttl > 0 {
			opts.Timeout = uint32(ttl.Seconds())
		}
	})
}

func (i *IPSetLinux) AddCIDR(addr netip.Prefix, ttl time.Duration) error {
	if addr.Addr().Is4() && i.tye == Inet6 {
		return ErrInetMismatch
	}
	if addr.Addr().Is6() && i.tye == Inet4 {
		return ErrInetMismatch
	}
	return i.nl.HandleAddr(IPSET_CMD_ADD, i.name, addr.Addr(), addr, func(opts *Options) {
		if ttl > 0 {
			opts.Timeout = uint32(ttl.Seconds())
		}
	})
}

func (i *IPSetLinux) DelIP(addr netip.Addr) error {
	if addr.Is4() && i.tye == Inet6 {
		return ErrInetMismatch
	}
	if addr.Is6() && i.tye == Inet4 {
		return ErrInetMismatch
	}
	return i.nl.HandleAddr(IPSET_CMD_DEL, i.name, addr, netip.Prefix{})
}

func (i *IPSetLinux) DelCIDR(addr netip.Prefix) error {
	if addr.Addr().Is4() && i.tye == Inet6 {
		return ErrInetMismatch
	}
	if addr.Addr().Is6() && i.tye == Inet4 {
		return ErrInetMismatch
	}
	return i.nl.HandleAddr(IPSET_CMD_DEL, i.name, addr.Addr(), addr)
}

func (i *IPSetLinux) FlushAll() error {
	return i.nl.FlushSet(i.name)
}
