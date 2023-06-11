//go:build !linux

package internal

import (
	"errors"
	"net/netip"
	"time"
)

var ErrOSNotSupported = errors.New("nftset: OS not supported")

type NftSetOther struct{}

func New(_ string, _ string, _ InetType) (*NftSetOther, error) {
	return nil, ErrOSNotSupported
}

func (n *NftSetOther) Name() string {
	return ""
}

func (n *NftSetOther) Close() error {
	return ErrOSNotSupported
}

func (n *NftSetOther) AddIP(_ netip.Addr, _ time.Duration) error {
	return ErrOSNotSupported
}

func (n *NftSetOther) AddCIDR(_ netip.Prefix, _ time.Duration) error {
	return ErrOSNotSupported
}

func (n *NftSetOther) DelIP(_ netip.Addr) error {
	return ErrOSNotSupported
}

func (n *NftSetOther) DelCIDR(_ netip.Prefix) error {
	return ErrOSNotSupported
}

func (n *NftSetOther) FlushAll() error {
	return ErrOSNotSupported
}
