package hosts

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

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/lib/tools"
	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/log"

	"github.com/go-chi/chi"
	"github.com/miekg/dns"
)

var (
	_ adapter.ExecPlugin        = (*Hosts)(nil)
	_ adapter.Starter           = (*Hosts)(nil)
	_ adapter.WithContextLogger = (*Hosts)(nil)
	_ adapter.APIHandler        = (*Hosts)(nil)
)

const PluginType = "hosts"

func init() {
	adapter.RegisterExecPlugin(PluginType, NewHosts)
}

type Hosts struct {
	tag        string
	logger     log.ContextLogger
	insideRule *map[*rule][]netip.Addr
	file       []string
	fileRule   atomic.Pointer[map[*rule][]netip.Addr]
	reloadLock sync.Mutex
}

type option struct {
	Rule types.Listable[string] `config:"rule"`
	File types.Listable[string] `config:"file"`
}

func NewHosts(tag string, args map[string]any) (adapter.ExecPlugin, error) {
	h := &Hosts{
		tag: tag,
	}

	var op option
	err := tools.NewMapStructureDecoderWithResult(&op).Decode(args)
	if err != nil {
		return nil, fmt.Errorf("decode config fail: %s", err)
	}
	if op.Rule != nil && len(op.Rule) > 0 {
		insideRule, err := loadFromArray(op.Rule)
		if err != nil {
			return nil, fmt.Errorf("parse args fail: %s", err)
		}
		h.insideRule = insideRule
	}
	if h.insideRule == nil && len(op.File) == 0 {
		return nil, fmt.Errorf("parse args fail: file is empty")
	}
	h.file = op.File
	return h, nil
}

func (h *Hosts) Tag() string {
	return h.tag
}

func (h *Hosts) Type() string {
	return PluginType
}

func (h *Hosts) Start() error {
	rules := make([]*map[*rule][]netip.Addr, 0)
	for _, f := range h.file {
		ru, err := loadHostFile(f)
		if err != nil {
			return fmt.Errorf("load hosts file %s fail: %s", f, err)
		}
		rules = append(rules, ru)
	}
	rule := mergeRules(rules...)
	h.fileRule.Store(rule)
	h.logger.Info(fmt.Sprintf("read rules success: %d", len(*rule)))
	return nil
}

func (h *Hosts) WithContextLogger(contextLogger log.ContextLogger) {
	h.logger = contextLogger
}

func (h *Hosts) APIHandler() http.Handler {
	r := chi.NewRouter()
	r.Get("/reload", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		go h.reloadRule(r.Context())
	})
	return r
}

func (h *Hosts) reloadRule(ctx context.Context) {
	if !h.reloadLock.TryLock() {
		return
	}
	defer h.reloadLock.Unlock()
	h.logger.InfoContext(ctx, "reload rule...")
	rules := make([]*map[*rule][]netip.Addr, 0)
	for _, f := range h.file {
		ru, err := loadHostFile(f)
		if err != nil {
			h.logger.ErrorContext(ctx, fmt.Sprintf("load hosts file %s fail: %s", f, err))
			continue
		}
		rules = append(rules, ru)
	}
	rule := mergeRules(rules...)
	h.fileRule.Store(rule)
	h.logger.InfoContext(ctx, fmt.Sprintf("reload rule success: %d", len(*rule)))
}

func (h *Hosts) Exec(ctx context.Context, _ map[string]any, dnsCtx *adapter.DNSContext) (constant.ReturnMode, error) {
	switch dnsCtx.ReqMsg.Question[0].Qtype {
	case dns.TypeA:
	case dns.TypeAAAA:
	default:
		return constant.Continue, nil
	}
	ruleGroup := make([]*map[*rule][]netip.Addr, 0)
	fileRule := h.fileRule.Load()
	if fileRule == nil {
		return constant.ReturnAll, fmt.Errorf("file rule not found")
	}
	ruleGroup = append(ruleGroup, fileRule)
	if h.insideRule != nil {
		ruleGroup = append(ruleGroup, h.insideRule)
	}
	domain := dnsCtx.ReqMsg.Question[0].Name
	if dns.IsFqdn(domain) {
		domain = domain[:len(domain)-1]
	}
	for _, rule := range ruleGroup {
		for r, ips := range *rule {
			matchType, matchRule, match := r.match(domain)
			if match {
				h.logger.InfoContext(ctx, fmt.Sprintf("match rule: %s => %s", matchType, matchRule))
				switch dnsCtx.ReqMsg.Question[0].Qtype {
				case dns.TypeA:
					rr := make([]dns.RR, 0)
					for _, ip := range ips {
						if ip.Is4() {
							rrItem := &dns.A{
								Hdr: dns.RR_Header{
									Name:   dnsCtx.ReqMsg.Question[0].Name,
									Rrtype: dns.TypeA,
									Class:  dns.ClassINET,
								},
								A: ip.AsSlice(),
							}
							rr = append(rr, rrItem)
						}
					}
					newRespMsg := &dns.Msg{}
					newRespMsg.SetReply(dnsCtx.ReqMsg)
					newRespMsg.Used(rr)
					dnsCtx.RespMsg = newRespMsg
				case dns.TypeAAAA:
					rr := make([]dns.RR, 0)
					for _, ip := range ips {
						if ip.Is6() {
							rrItem := &dns.AAAA{
								Hdr: dns.RR_Header{
									Name:   dnsCtx.ReqMsg.Question[0].Name,
									Rrtype: dns.TypeAAAA,
									Class:  dns.ClassINET,
								},
								AAAA: ip.AsSlice(),
							}
							rr = append(rr, rrItem)
						}
					}
					newRespMsg := &dns.Msg{}
					newRespMsg.SetReply(dnsCtx.ReqMsg)
					newRespMsg.Used(rr)
					dnsCtx.RespMsg = newRespMsg
				}
				return constant.Continue, nil
			}
		}
	}
	return constant.Continue, nil
}

type rule struct {
	full   string
	suffix string
}

func (r *rule) match(domain string) (string, string, bool) {
	if r.full != "" {
		if r.full == domain {
			return "domain_full", r.full, true
		}
	}
	if r.suffix != "" {
		if strings.HasSuffix(domain, r.suffix) {
			return "domain_suffix", r.suffix, true
		}
	}
	return "", "", false
}

func (r *rule) String() string {
	if r.full != "" {
		return fmt.Sprintf("full:%s", r.full)
	}
	if r.suffix != "" {
		return fmt.Sprintf("suffix:%s", r.suffix)
	}
	return ""
}

func loadHostFile(filename string) (*map[*rule][]netip.Addr, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	reader := bytes.NewReader(content)
	scanner := bufio.NewScanner(reader)
	rules := make(map[*rule][]netip.Addr)
	domainMap := make(map[string]*rule)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		domain := fields[0]
		ipStr := fields[1:]
		rule := &rule{}
		if strings.HasPrefix(domain, "full:") {
			rule.full = domain[5:]
		} else if strings.HasPrefix(domain, "suffix:") {
			rule.suffix = domain[7:]
		} else {
			return nil, fmt.Errorf("invalid domain: %s", domain)
		}
		ips := make([]netip.Addr, 0, len(ipStr))
		for _, ip := range ipStr {
			ipAddr, err := netip.ParseAddr(ip)
			if err != nil {
				return nil, fmt.Errorf("invalid ip: %s", ip)
			}
			ips = append(ips, ipAddr)
		}
		if oldRule, ok := domainMap[domain]; ok {
			oldAddrs := rules[oldRule]
			for _, ip := range ips {
				found := false
				for _, oldAddr := range oldAddrs {
					if oldAddr.Compare(ip) == 0 {
						found = true
						break
					}
				}
				if !found {
					oldAddrs = append(oldAddrs, ip)
				}
			}
			rules[oldRule] = oldAddrs
		} else {
			rules[rule] = ips
			domainMap[domain] = rule
		}
	}
	return &rules, nil
}

func loadFromArray(arr []string) (*map[*rule][]netip.Addr, error) {
	rules := make(map[*rule][]netip.Addr)
	domainMap := make(map[string]*rule)
	for _, line := range arr {
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		domain := fields[0]
		ipStr := fields[1:]
		rule := &rule{}
		if strings.HasPrefix(domain, "full:") {
			rule.full = domain[5:]
		} else if strings.HasPrefix(domain, "suffix:") {
			rule.suffix = domain[7:]
		} else {
			return nil, fmt.Errorf("invalid domain: %s", domain)
		}
		ips := make([]netip.Addr, 0, len(ipStr))
		for _, ip := range ipStr {
			ipAddr, err := netip.ParseAddr(ip)
			if err != nil {
				return nil, fmt.Errorf("invalid ip: %s", ip)
			}
			ips = append(ips, ipAddr)
		}
		if oldRule, ok := domainMap[domain]; ok {
			oldAddrs := rules[oldRule]
			for _, ip := range ips {
				found := false
				for _, oldAddr := range oldAddrs {
					if oldAddr.Compare(ip) == 0 {
						found = true
						break
					}
				}
				if !found {
					oldAddrs = append(oldAddrs, ip)
				}
			}
			rules[oldRule] = oldAddrs
		} else {
			rules[rule] = ips
			domainMap[domain] = rule
		}
	}
	return &rules, nil
}

func mergeRules(rules ...*map[*rule][]netip.Addr) *map[*rule][]netip.Addr {
	m := make(map[*rule][]netip.Addr)
	for _, r := range rules {
		for rule, ips := range *r {
			if _, ok := m[rule]; !ok {
				m[rule] = make([]netip.Addr, 0, len(ips))
			}
			m[rule] = append(m[rule], ips...)
		}
	}
	ruleNew := make(map[*rule][]netip.Addr)
	ru := make(map[string]*rule)
	for rule := range m {
		if s, ok := ru[rule.String()]; ok {
			oldAddrs := ruleNew[s]
			for _, ip := range m[rule] {
				found := false
				for _, oldAddr := range oldAddrs {
					if oldAddr.Compare(ip) == 0 {
						found = true
						break
					}
				}
				if !found {
					oldAddrs = append(oldAddrs, ip)
				}
			}
			ruleNew[ru[rule.String()]] = oldAddrs
		} else {
			ru[rule.String()] = rule
			ruleNew[rule] = m[rule]
		}
	}
	return &ruleNew
}
