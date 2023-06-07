package host

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
	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/log"

	"github.com/go-chi/chi"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

var _ adapter.ExecPlugin = (*Host)(nil)

const PluginType = "host"

func init() {
	adapter.RegisterExecPlugin(PluginType, NewHost)
}

type Host struct {
	tag        string
	logger     log.ContextLogger
	file       []string
	rule       atomic.Pointer[map[*rule][]netip.Addr]
	reloadLock sync.Mutex
}

type option struct {
	File types.Listable[string] `yaml:"file"`
}

func NewHost(tag string, args map[string]any) (adapter.ExecPlugin, error) {
	h := &Host{
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
	if len(op.File) == 0 {
		return nil, fmt.Errorf("parse args fail: file is empty")
	}
	h.file = op.File

	return h, nil
}

func (h *Host) Tag() string {
	return h.tag
}

func (h *Host) Type() string {
	return PluginType
}

func (h *Host) Start() error {
	rules := make([]*map[*rule][]netip.Addr, 0)
	for _, f := range h.file {
		ru, err := loadHostFile(f)
		if err != nil {
			return fmt.Errorf("load host file %s fail: %s", f, err)
		}
		rules = append(rules, ru)
	}
	rule := mergeRules(rules...)
	h.rule.Store(rule)
	h.logger.Info(fmt.Sprintf("read rules success: %d", len(*rule)))
	return nil
}

func (h *Host) Close() error {
	return nil
}

func (h *Host) WithContext(_ context.Context) {
}

func (h *Host) WithLogger(logger log.ContextLogger) {
	h.logger = logger
}

func (h *Host) WithCore(_ adapter.ExecPluginCore) {
}

func (h *Host) APIHandler() http.Handler {
	r := chi.NewRouter()
	r.Get("/reload", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		go h.reloadRule()
	})
	return r
}

func (h *Host) reloadRule() {
	if !h.reloadLock.TryLock() {
		return
	}
	defer h.reloadLock.Unlock()
	h.logger.Info("reload rule...")
	rules := make([]*map[*rule][]netip.Addr, 0)
	for _, f := range h.file {
		ru, err := loadHostFile(f)
		if err != nil {
			h.logger.Error(fmt.Sprintf("load host file %s fail: %s", f, err))
			continue
		}
		rules = append(rules, ru)
	}
	rule := mergeRules(rules...)
	h.rule.Store(rule)
	h.logger.Info(fmt.Sprintf("reload rule success: %d", len(*rule)))
}

func (h *Host) Exec(ctx context.Context, _ map[string]any, dnsCtx *adapter.DNSContext) bool {
	switch dnsCtx.ReqMsg.Question[0].Qtype {
	case dns.TypeA:
	case dns.TypeAAAA:
	default:
		return true
	}
	rule := h.rule.Load()
	if rule == nil {
		return true
	}
	domain := dnsCtx.ReqMsg.Question[0].Name
	if dns.IsFqdn(domain) {
		domain = domain[:len(domain)-1]
	}
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
			default:
				return true
			}
		}
	}
	return true
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
