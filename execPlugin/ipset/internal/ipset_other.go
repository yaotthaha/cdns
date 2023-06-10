//go:build !linux

package internal

import (
	"errors"
	"net/netip"
	"time"
)

var ErrOSNotSupported = errors.New("ipset: OS not supported")

type IPSetOther struct{}

func New(_ string, _ InetType) (*IPSetOther, error) {
	return nil, ErrOSNotSupported
}

func (i *IPSetOther) Name() string {
	return ""
}

func (i *IPSetOther) AddIP(_ netip.Addr, _ time.Duration) error {
	return ErrOSNotSupported
}

func (i *IPSetOther) AddCIDR(_ netip.Prefix, _ time.Duration) error {
	return ErrOSNotSupported
}

func (i *IPSetOther) DelIP(_ netip.Addr) error {
	return ErrOSNotSupported
}

func (i *IPSetOther) DelCIDR(_ netip.Prefix) error {
	return ErrOSNotSupported
}

func (i *IPSetOther) FlushAll() error {
	return ErrOSNotSupported
}
