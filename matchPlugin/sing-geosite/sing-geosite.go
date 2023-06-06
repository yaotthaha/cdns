package sing_geosite

import (
	"context"
	"fmt"
	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/matchPlugin/sing-geosite/geosite"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

const PluginType = "sing-geosite"

var _ adapter.MatchPlugin = (*SingGeoSite)(nil)

func init() {
	adapter.RegisterMatchPlugin(PluginType, NewSingGeoSite)
}

type SingGeoSite struct {
	tag        string
	ctx        context.Context
	logger     log.ContextLogger
	reloadLock sync.Mutex
	file       string
	code       []string
	codeMap    atomic.Pointer[map[string]*domainItem]
}

type domainItem struct {
	full    []string
	suffix  []string
	keyword []string
	regex   []*regexp.Regexp
}

func (d *domainItem) match(ctx context.Context, domain string) (string, string, bool) {
	if d.full != nil && len(d.full) > 0 {
		for _, f := range d.full {
			select {
			case <-ctx.Done():
				return "", "", false
			default:
			}
			if f == domain {
				return "domain_full", f, true
			}
		}
	}
	if d.suffix != nil && len(d.suffix) > 0 {
		for _, f := range d.suffix {
			select {
			case <-ctx.Done():
				return "", "", false
			default:
			}
			if strings.HasSuffix(domain, f) {
				return "domain_suffix", f, true
			}
		}
	}
	if d.keyword != nil && len(d.keyword) > 0 {
		for _, f := range d.keyword {
			select {
			case <-ctx.Done():
				return "", "", false
			default:
			}
			if strings.Contains(domain, f) {
				return "domain_keyword", f, true
			}
		}
	}
	if d.regex != nil && len(d.regex) > 0 {
		for _, f := range d.regex {
			select {
			case <-ctx.Done():
				return "", "", false
			default:
			}
			if f.MatchString(domain) {
				return "domain_regex", f.String(), true
			}
		}
	}
	return "", "", false
}

type option struct {
	File string                 `yaml:"file"`
	Code types.Listable[string] `yaml:"code"`
}

func NewSingGeoSite(tag string, args map[string]any) (adapter.MatchPlugin, error) {
	c := &SingGeoSite{
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

	if op.File == "" {
		return nil, fmt.Errorf("file is empty")
	}
	c.file = op.File
	if op.Code != nil && len(op.Code) > 0 {
		c.code = op.Code
	}

	return c, nil
}

func (s *SingGeoSite) Tag() string {
	return s.tag
}

func (s *SingGeoSite) Type() string {
	return PluginType
}

func (s *SingGeoSite) Start() error {
	codeMap, err := s.loadGeoSite()
	if err != nil {
		return err
	}
	s.logger.Info(fmt.Sprintf("load geosite success: %d", len(*codeMap)))
	s.codeMap.Store(codeMap)
	return nil
}

func (s *SingGeoSite) Close() error {
	return nil
}

func (s *SingGeoSite) WithContext(ctx context.Context) {
	s.ctx = ctx
}

func (s *SingGeoSite) WithLogger(contextLogger log.ContextLogger) {
	s.logger = contextLogger
}

func (s *SingGeoSite) APIHandler() http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		go s.reloadGeoSite()
	}
	return http.HandlerFunc(fn)
}

func (s *SingGeoSite) reloadGeoSite() {
	if !s.reloadLock.TryLock() {
		return
	}
	defer s.reloadLock.Unlock()
	s.logger.Info("reload geosite...")
	codeMap, err := s.loadGeoSite()
	if err != nil {
		s.logger.Error(fmt.Sprintf("reload geosite fail: %s", err))
		return
	}
	s.codeMap.Store(codeMap)
	s.logger.Info("reload geosite success")
}

func (s *SingGeoSite) Match(ctx context.Context, args map[string]any, dnsCtx *adapter.DNSContext) bool {
	question := dnsCtx.ReqMsg.Question[0]
	switch question.Qtype {
	case dns.TypeA:
	case dns.TypeAAAA:
	case dns.TypeCNAME:
	default:
		return false
	}
	domain := question.Name
	if dns.IsFqdn(domain) {
		domain = strings.Trim(domain, ".")
	}
	codeMap := s.codeMap.Load()
	if codeMap == nil {
		return false
	}
	codeAnyListAny, ok := args["code"]
	if ok {
		codeAnyList, ok := codeAnyListAny.([]any)
		if ok {
			codeList := make([]string, 0)
			for _, codeAny := range codeAnyList {
				code, ok := codeAny.(string)
				if !ok {
					s.logger.ErrorContext(ctx, fmt.Sprintf("code type error: %T", args["code"]))
					return false
				}
				codeList = append(codeList, code)
			}
			if len(codeList) > 0 {
				for _, code := range codeList {
					dItem, ok := (*codeMap)[code]
					if ok {
						matchType, matchStr, match := dItem.match(ctx, domain)
						if match {
							s.logger.DebugContext(ctx, fmt.Sprintf("match sing-geosite: code ==> %s, type ==> %s, rule ==> %s", code, matchType, matchStr))
							return true
						} else {
							return false
						}
					} else {
						s.logger.ErrorContext(ctx, fmt.Sprintf("code %s not found", code))
						return false
					}
				}
			}
			return false
		}
		codeItem, ok := codeAnyListAny.(string)
		if ok {
			dItem, ok := (*codeMap)[codeItem]
			if ok {
				matchType, matchStr, match := dItem.match(ctx, domain)
				if match {
					s.logger.DebugContext(ctx, fmt.Sprintf("match sing-geosite: code ==> %s, type ==> %s, rule ==> %s", codeItem, matchType, matchStr))
					return true
				} else {
					return false
				}
			} else {
				s.logger.ErrorContext(ctx, fmt.Sprintf("code %s not found", codeItem))
				return false
			}
		}
		s.logger.ErrorContext(ctx, fmt.Sprintf("code type error: %T", args["code"]))
		return false
	}
	for code, dItem := range *codeMap {
		matchType, matchStr, match := dItem.match(ctx, domain)
		if match {
			s.logger.DebugContext(ctx, fmt.Sprintf("match sing-geosite: code ==> %s, type ==> %s, rule ==> %s", code, matchType, matchStr))
			return true
		}
	}
	return false
}

func (s *SingGeoSite) loadGeoSite() (*map[string]*domainItem, error) {
	reader, codes, err := geosite.Open(s.file)
	if err != nil {
		return nil, fmt.Errorf("read geosite file fail: %s", err)
	}
	if len(codes) == 0 {
		return nil, fmt.Errorf("no geosite code found")
	}
	if s.code != nil {
		for _, code := range s.code {
			find := false
			for _, codeExist := range codes {
				if code == codeExist {
					find = true
					break
				}
			}
			if !find {
				return nil, fmt.Errorf("code %s not found", code)
			}
		}
		codes = s.code
	}
	codeMap := make(map[string]*domainItem)
	for _, code := range codes {
		items, err := reader.Read(code)
		if err != nil {
			return nil, fmt.Errorf("read geosite item fail: %s", err)
		}
		if items != nil && len(items) > 0 {
			dItem := &domainItem{}
			for _, item := range items {
				switch item.Type {
				case geosite.RuleTypeDomain:
					dItem.full = append(dItem.full, item.Value)
				case geosite.RuleTypeDomainSuffix:
					dItem.suffix = append(dItem.suffix, item.Value)
				case geosite.RuleTypeDomainKeyword:
					dItem.keyword = append(dItem.keyword, item.Value)
				case geosite.RuleTypeDomainRegex:
					regex, err := regexp.Compile(item.Value)
					if err != nil {
						return nil, fmt.Errorf("compile regex %s fail: %s", item.Value, err)
					}
					dItem.regex = append(dItem.regex, regex)
				}
			}
			codeMap[code] = dItem
		} else {
			return nil, fmt.Errorf("no geosite item found, code: %s", code)
		}
	}
	return &codeMap, nil
}
