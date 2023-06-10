package internal

import (
	"net/netip"
	"time"
)

type InetType string

const (
	Inet4 InetType = "4"
	Inet6 InetType = "6"
)

type IPSet interface {
	Name() string
	AddIP(netip.Addr, time.Duration) error
	AddCIDR(netip.Prefix, time.Duration) error
	DelIP(netip.Addr) error
	DelCIDR(netip.Prefix) error
	FlushAll() error
}
