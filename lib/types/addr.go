package types

import (
	"fmt"
	"net/netip"
)

type Addr struct {
	netip.Addr
}

func (a *Addr) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	err := unmarshal(&s)
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return err
	}
	if !addr.IsValid() {
		return fmt.Errorf("invalid address: %s", s)
	}
	a.Addr = addr
	return nil
}

func (a Addr) MarshalYAML() (interface{}, error) {
	return a.String(), nil
}
