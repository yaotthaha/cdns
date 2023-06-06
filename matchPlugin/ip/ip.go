package ip

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/log"

	"github.com/go-chi/chi"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

const PluginType = "ip"

func init() {
	adapter.RegisterMatchPlugin(PluginType, NewIP)
}

var _ adapter.MatchPlugin = (*IP)(nil)

type IP struct {
	tag        string
	logger     log.ContextLogger
	reloadLock sync.Mutex
	fileList   []string
	insideRule atomic.Pointer[rule]
	fileRule   atomic.Pointer[rule]
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
	insideRule := &rule{}
	var haveRule int
	if op.IP != nil && len(op.IP) > 0 {
		ips := make([]netip.Addr, 0)
		for _, ipStr := range op.IP {
			ip, err := netip.ParseAddr(ipStr)
			if err != nil {
				return nil, fmt.Errorf("parse ip %s fail: %s", ipStr, err)
			}
			ips = append(ips, ip)
		}
		if len(ips) > 0 {
			insideRule.ip = ips
			haveRule++
		}
	}
	if op.CIDR != nil && len(op.CIDR) > 0 {
		cidrs := make([]netip.Prefix, 0)
		for _, cidrStr := range op.CIDR {
			cidr, err := netip.ParsePrefix(cidrStr)
			if err != nil {
				return nil, fmt.Errorf("parse cidr %s fail: %s", cidrStr, err)
			}
			cidrs = append(cidrs, cidr)
		}
		if len(cidrs) > 0 {
			insideRule.cidr = cidrs
			haveRule++
		}
	}
	if haveRule > 0 {
		d.insideRule.Store(insideRule)
	}
	if op.File != nil && len(op.File) > 0 {
		haveRule++
	}

	if haveRule == 0 {
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
		rules := make([]*rule, 0)
		for _, filename := range i.fileList {
			i.logger.Info(fmt.Sprintf("loading ip file: %s", filename))
			ruleItem, err := readRules(filename)
			if err != nil {
				return err
			}
			rules = append(rules, ruleItem)
			i.logger.Info(fmt.Sprintf("load ip file: %s success", filename))
		}
		fileRule := mergeRule(rules...)
		var (
			ipN   int
			cidrN int
		)
		ipN, cidrN = fileRule.length()
		i.logger.Info(fmt.Sprintf("file ip rule: ip: %d, cidr: %d", ipN, cidrN))
		i.fileRule.Store(fileRule)
	}
	if insideRule := i.insideRule.Load(); insideRule != nil {
		var (
			ipN   int
			cidrN int
		)
		ipN, cidrN = insideRule.length()
		i.logger.Info(fmt.Sprintf("inside ip rule: ip: %d, cidr: %d", ipN, cidrN))
	}
	return nil
}

func (i *IP) Close() error {
	return nil
}

func (i *IP) WithContext(_ context.Context) {
}

func (i *IP) WithLogger(contextLogger log.ContextLogger) {
	i.logger = contextLogger
}

func (i *IP) APIHandler() http.Handler {
	r := chi.NewRouter()
	r.Get("/reload", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		go i.reloadFileRule()
	})
	return r
}

func (i *IP) reloadFileRule() {
	if !i.reloadLock.TryLock() {
		return
	}
	defer i.reloadLock.Unlock()
	startTime := time.Now()
	i.logger.Info("reload file rule...")
	if i.fileList != nil {
		files := make([]*rule, 0)
		for _, f := range i.fileList {
			rule, err := readRules(f)
			if err != nil {
				i.logger.Error(fmt.Sprintf("reload file rule fail, file %s, err: %s", f, err))
				return
			}
			files = append(files, rule)
		}
		fileRule := mergeRule(files...)
		var (
			ipN   int
			cidrN int
		)
		ipN, cidrN = fileRule.length()
		i.logger.Info(fmt.Sprintf("file ip rule: ip: %d, cidr: %d", ipN, cidrN))
		i.fileRule.Store(fileRule)
		i.logger.Info("reload file rule success, cost: %s", time.Since(startTime).String())
	} else {
		i.logger.Info("no file to reload")
	}
}

func (i *IP) Match(ctx context.Context, _ map[string]any, dnsCtx *adapter.DNSContext) bool {
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
	insideRule := i.insideRule.Load()
	if insideRule != nil {
		matchType, matchRule, match := insideRule.match(ctx, respIP)
		if match {
			i.logger.DebugContext(ctx, fmt.Sprintf("match %s: %s", matchType, matchRule))
			return true
		}
	}
	select {
	case <-ctx.Done():
		return false
	default:
	}
	fileRule := i.fileRule.Load()
	if fileRule != nil {
		matchType, matchRule, match := fileRule.match(ctx, respIP)
		if match {
			i.logger.DebugContext(ctx, fmt.Sprintf("match %s: %s", matchType, matchRule))
			return true
		}
	}
	return false
}

type rule struct {
	ip   []netip.Addr
	cidr []netip.Prefix
}

func readRules(filename string) (*rule, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	reader := bytes.NewReader(content)
	scanner := bufio.NewScanner(reader)
	ruleItem := &rule{}
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		line = strings.TrimSpace(line)
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

func mergeRule(rules ...*rule) *rule {
	ruleItem := &rule{}
	for _, r := range rules {
		if r.ip != nil && len(r.ip) > 0 {
			if ruleItem.ip == nil {
				ruleItem.ip = make([]netip.Addr, 0)
			}
			ruleItem.ip = append(ruleItem.ip, r.ip...)
		}
		if r.cidr != nil && len(r.cidr) > 0 {
			if ruleItem.cidr == nil {
				ruleItem.cidr = make([]netip.Prefix, 0)
			}
			ruleItem.cidr = append(ruleItem.cidr, r.cidr...)
		}
	}
	return ruleItem
}

func (r *rule) match(ctx context.Context, respIP []netip.Addr) (string, string, bool) {
	if r.ip != nil {
		for _, ip := range respIP {
			for _, ruleIP := range r.ip {
				select {
				case <-ctx.Done():
					return "", "", false
				default:
				}
				if ruleIP.Compare(ip) == 0 {
					return "ip", ruleIP.String(), true
				}
			}
		}
	}
	if r.cidr != nil {
		for _, ip := range respIP {
			for _, ruleCIDR := range r.cidr {
				select {
				case <-ctx.Done():
					return "", "", false
				default:
				}
				if ruleCIDR.Contains(ip) {
					return "cidr", ruleCIDR.String(), true
				}
			}
		}
	}
	return "", "", false
}

func (r *rule) length() (int, int) {
	var (
		ipN   int
		cidrN int
	)
	if r.ip != nil {
		ipN = len(r.ip)
	}
	if r.cidr != nil {
		cidrN = len(r.cidr)
	}
	return ipN, cidrN
}
