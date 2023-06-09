package ecs

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/log"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

var _ adapter.ExecPlugin = (*ECS)(nil)

const PluginType = "ecs"

func init() {
	adapter.RegisterExecPlugin(PluginType, NewECS)
}

type ECS struct {
	tag    string
	logger log.ContextLogger

	prefix4 netip.Prefix
	prefix6 netip.Prefix
}

type option struct {
	IP4   string `yaml:"ip4"`
	IP6   string `yaml:"ip6"`
	Mask4 uint8  `yaml:"mask4"`
	Mask6 uint8  `yaml:"mask6"`
}

func NewECS(tag string, args map[string]any) (adapter.ExecPlugin, error) {
	e := &ECS{
		tag: tag,
	}

	optionBytes, err := yaml.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("parse args fail: %s", err)
	}
	var op option
	err = yaml.Unmarshal(optionBytes, &op)
	if err != nil {
		return nil, fmt.Errorf("parse args fail: %s", err)
	}

	var done bool
	if op.IP4 != "" {
		ip, err := netip.ParseAddr(op.IP4)
		if err != nil {
			return nil, fmt.Errorf("invalid ip4: %s", err)
		}
		mask4 := 32
		if op.Mask4 > 0 {
			if op.Mask4 > 32 {
				return nil, fmt.Errorf("invalid mask4: %d", op.Mask4)
			}
			mask4 = int(op.Mask4)
		}
		e.prefix4 = netip.PrefixFrom(ip, mask4)
		done = true
	}
	if op.IP6 != "" {
		ip, err := netip.ParseAddr(op.IP6)
		if err != nil {
			return nil, fmt.Errorf("invalid ip6: %s", err)
		}
		mask6 := 32
		if op.Mask6 > 0 {
			if op.Mask6 > 128 {
				return nil, fmt.Errorf("invalid mask6: %d", op.Mask6)
			}
			mask6 = int(op.Mask6)
		}
		e.prefix6 = netip.PrefixFrom(ip, mask6)
		done = true
	}

	if !done {
		return nil, fmt.Errorf("invalid args")
	}

	return e, nil
}

func (e *ECS) Tag() string {
	return e.tag
}

func (e *ECS) Type() string {
	return PluginType
}

func (e *ECS) Start() error {
	return nil
}

func (e *ECS) Close() error {
	return nil
}

func (e *ECS) WithContext(_ context.Context) {
}

func (e *ECS) WithLogger(logger log.ContextLogger) {
	e.logger = logger
}

func (e *ECS) WithCore(_ adapter.ExecPluginCore) {
}

func (e *ECS) APIHandler() http.Handler {
	return nil
}

func (e *ECS) Exec(ctx context.Context, _ map[string]any, dnsCtx *adapter.DNSContext) bool {
	reqMsg := dnsCtx.ReqMsg
	if reqMsg.Question[0].Qtype == dns.TypeA && e.prefix4.IsValid() {
		o := new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		es := new(dns.EDNS0_SUBNET)
		es.Code = dns.EDNS0SUBNET
		es.Family = 1
		es.SourceNetmask = uint8(e.prefix4.Bits())
		es.SourceScope = 0
		es.Address = e.prefix4.Masked().Addr().AsSlice()
		o.Option = append(o.Option, es)
		reqMsg.Extra = append(reqMsg.Extra, o)
		e.logger.DebugContext(ctx, fmt.Sprintf("add ecs: ip: %s, mask: %d", e.prefix4.Masked().Addr().String(), e.prefix4.Bits()))
	}
	if reqMsg.Question[0].Qtype == dns.TypeAAAA && e.prefix6.IsValid() {
		o := new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		es := new(dns.EDNS0_SUBNET)
		es.Code = dns.EDNS0SUBNET
		es.Family = 2
		es.SourceNetmask = uint8(e.prefix6.Bits())
		es.SourceScope = 0
		es.Address = e.prefix6.Masked().Addr().AsSlice()
		o.Option = append(o.Option, es)
		reqMsg.Extra = append(reqMsg.Extra, o)
		e.logger.DebugContext(ctx, fmt.Sprintf("add ecs: ip: %s, mask: %d", e.prefix6.Masked().Addr().String(), e.prefix6.Bits()))
	}
	return true
}
