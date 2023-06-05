package ip

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/log"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

const PluginType = "ip"

func init() {
	adapter.RegisterMatchPlugin(PluginType, NewIP)
}

var _ adapter.MatchPlugin = (*IP)(nil)

type IP struct {
	tag      string
	logger   log.ContextLogger
	fileList []string

	ip   []netip.Addr
	cidr []netip.Prefix
}

type option struct {
	File types.Listable[string] `yaml:"file"`
	IP   types.Listable[string] `yaml:"ip"`
	CIDR types.Listable[string] `yaml:"cidr"`
}

func NewIP(tag string, args map[string]any) (adapter.MatchPlugin, error) {
	d := &IP{
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

	var haveRule bool
	if op.IP != nil && len(op.IP) > 0 {
		d.ip = make([]netip.Addr, 0)
		for _, ipStr := range op.IP {
			ip, err := netip.ParseAddr(ipStr)
			if err != nil {
				return nil, fmt.Errorf("parse ip %s fail: %s", ipStr, err)
			}
			d.ip = append(d.ip, ip)
		}
		if len(d.ip) > 0 {
			haveRule = true
		}
	}
	if op.CIDR != nil && len(op.CIDR) > 0 {
		d.cidr = make([]netip.Prefix, 0)
		for _, cidrStr := range op.CIDR {
			cidr, err := netip.ParsePrefix(cidrStr)
			if err != nil {
				return nil, fmt.Errorf("parse cidr %s fail: %s", cidrStr, err)
			}
			d.cidr = append(d.cidr, cidr)
		}
		if len(d.cidr) > 0 {
			haveRule = true
		}
	}
	if op.File != nil && len(op.File) > 0 {
		haveRule = true
	}

	if !haveRule {
		return nil, fmt.Errorf("no rules found")
	}

	return d, nil
}

func (i *IP) Tag() string {
	return i.tag
}

func (i *IP) Type() string {
	return PluginType
}

func (i *IP) Start() error {
	if i.fileList != nil {
		for _, filename := range i.fileList {
			i.logger.Info(fmt.Sprintf("loading domain file: %s", filename))
			ruleItem, err := readRules(filename)
			if err != nil {
				return err
			}
			if ruleItem.cidr != nil && len(ruleItem.cidr) > 0 {
				if i.cidr == nil {
					i.cidr = make([]netip.Prefix, 0)
				}
				i.cidr = append(i.cidr, ruleItem.cidr...)
			}
			if ruleItem.ip != nil && len(ruleItem.ip) > 0 {
				if i.ip == nil {
					i.ip = make([]netip.Addr, 0)
				}
				i.ip = append(i.ip, ruleItem.ip...)
			}
			i.logger.Info(fmt.Sprintf("load domain file: %s success", filename))
		}
	}
	var (
		ipN   int
		cidrN int
	)
	if i.ip != nil {
		ipN = len(i.ip)
	}
	if i.cidr != nil {
		cidrN = len(i.cidr)
	}
	i.logger.Info(fmt.Sprintf("domain rule: ip: %d, cidr: %d", ipN, cidrN))
	return nil
}

func (i *IP) Close() error {
	return nil
}

func (i *IP) WithContext(ctx context.Context) {
}

func (i *IP) WithLogger(logger log.Logger) {
	i.logger = log.NewContextLogger(log.NewTagLogger(logger, fmt.Sprintf("match-plugin/%s/%s", PluginType, i.tag)))
}

func (i *IP) Match(ctx context.Context, args map[string]any, dnsCtx *adapter.DNSContext) bool {
	if dnsCtx.RespMsg == nil {
		return false
	}
	respIP := make([]netip.Addr, 0)
	for _, rr := range dnsCtx.RespMsg.Answer {
		switch r := rr.(type) {
		case *dns.A:
			ip, err := netip.ParseAddr(r.A.String())
			if err != nil {
				continue
			}
			respIP = append(respIP, ip)
		case *dns.AAAA:
			ip, err := netip.ParseAddr(r.AAAA.String())
			if err != nil {
				continue
			}
			respIP = append(respIP, ip)
		}
	}
	if len(respIP) == 0 {
		return false
	}
	if i.ip != nil {
		for _, ip := range respIP {
			for _, ruleIP := range i.ip {
				if ruleIP.Compare(ip) == 0 {
					i.logger.DebugContext(ctx, fmt.Sprintf("match ip: %s", ip.String()))
					return true
				}
			}
		}
	}
	if i.cidr != nil {
		for _, ip := range respIP {
			for _, ruleCIDR := range i.cidr {
				if ruleCIDR.Contains(ip) {
					i.logger.DebugContext(ctx, fmt.Sprintf("match cidr: %s", ruleCIDR.String()))
					return true
				}
			}
		}
	}
	return false
}

type ruleItem struct {
	ip   []netip.Addr
	cidr []netip.Prefix
}

func readRules(filename string) (*ruleItem, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	reader := bytes.NewReader(content)
	scanner := bufio.NewScanner(reader)
	ruleItem := &ruleItem{}
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		cidr, err := netip.ParsePrefix(line)
		if err == nil {
			ruleItem.cidr = append(ruleItem.cidr, cidr)
			continue
		}
		ip, err := netip.ParseAddr(line)
		if err == nil {
			ruleItem.ip = append(ruleItem.ip, ip)
			continue
		}
		return nil, fmt.Errorf("invalid rule: %s", line)
	}
	return ruleItem, nil
}
