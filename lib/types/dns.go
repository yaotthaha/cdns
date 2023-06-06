package types

import (
	"fmt"

	"github.com/miekg/dns"
)

type DNSQType uint16

func (d *DNSQType) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var v any
	err := unmarshal(&v)
	if err != nil {
		return err
	}
	switch value := v.(type) {
	case string:
		qType, loaded := dns.StringToType[value]
		if loaded {
			*d = DNSQType(qType)
			return nil
		}
		return fmt.Errorf("unknown qtype: %s", value)
	case int:
		*d = DNSQType(value)
		return nil
	default:
		return fmt.Errorf("unknown qtype: %s", value)
	}
}
