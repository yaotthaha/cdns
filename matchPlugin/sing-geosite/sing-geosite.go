package sing_geosite

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/lib/tools"
	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/matchPlugin/sing-geosite/geosite"

	regexp "github.com/dlclark/regexp2"
	"github.com/go-chi/chi"
	"github.com/miekg/dns"
)

const PluginType = "sing-geosite"

var (
	_ adapter.MatchPlugin       = (*SingGeoSite)(nil)
	_ adapter.Starter           = (*SingGeoSite)(nil)
	_ adapter.WithContext       = (*SingGeoSite)(nil)
	_ adapter.WithContextLogger = (*SingGeoSite)(nil)
	_ adapter.APIHandler        = (*SingGeoSite)(nil)
)

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

type domainItemMatch struct {
	typ string
	val string
}

func (d *domainItem) match(ctx context.Context, domain string) (string, string, bool) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	wg := sync.WaitGroup{}
	resChan := make(chan *domainItemMatch, 1)
	if d.full != nil && len(d.full) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, f := range d.full {
				select {
				case <-ctx.Done():
					return
				default:
					if f == domain {
						select {
						case resChan <- &domainItemMatch{
							typ: "domain_full",
							val: f,
						}:
						default:
						}
						return
					}
				}
			}
		}()
	}
	if d.suffix != nil && len(d.suffix) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, f := range d.suffix {
				select {
				case <-ctx.Done():
					return
				default:
					if strings.HasSuffix(domain, f) {
						select {
						case resChan <- &domainItemMatch{
							typ: "domain_suffix",
							val: f,
						}:
						default:
						}
						return
					}
				}
			}
		}()
	}
	if d.keyword != nil && len(d.keyword) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, f := range d.keyword {
				select {
				case <-ctx.Done():
					return
				default:
					if strings.Contains(domain, f) {
						select {
						case resChan <- &domainItemMatch{
							typ: "domain_keyword",
							val: f,
						}:
						default:
						}
						return
					}
				}
			}
		}()
	}
	if d.regex != nil && len(d.regex) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, f := range d.regex {
				select {
				case <-ctx.Done():
					return
				default:
					if match, err := f.MatchString(domain); err == nil && match {
						select {
						case resChan <- &domainItemMatch{
							typ: "domain_regex",
							val: f.String(),
						}:
						default:
						}
						return
					}
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		cancel()
	}()
	var resp *domainItemMatch
	select {
	case resp = <-resChan:
		cancel()
	case <-ctx.Done():
	}
	wg.Wait()
	close(resChan)
	if resp == nil {
		return "", "", false
	}
	return resp.typ, resp.val, true
}

type option struct {
	File string                 `config:"file"`
	Code types.Listable[string] `config:"code"`
}

func NewSingGeoSite(tag string, args map[string]any) (adapter.MatchPlugin, error) {
	c := &SingGeoSite{
		tag: tag,
	}

	var op option
	err := tools.NewMapStructureDecoderWithResult(&op).Decode(args)
	if err != nil {
		return nil, fmt.Errorf("decode config fail: %s", err)
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

func (s *SingGeoSite) WithContext(ctx context.Context) {
	s.ctx = ctx
}

func (s *SingGeoSite) WithContextLogger(contextLogger log.ContextLogger) {
	s.logger = contextLogger
}

func (s *SingGeoSite) APIHandler() http.Handler {
	r := chi.NewRouter()
	r.Get("/reload", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		go s.reloadGeoSite(r.Context())
	})
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	return r
}

func (s *SingGeoSite) reloadGeoSite(ctx context.Context) {
	if !s.reloadLock.TryLock() {
		return
	}
	defer s.reloadLock.Unlock()
	startTime := time.Now()
	s.logger.InfoContext(ctx, "reload geosite...")
	codeMap, err := s.loadGeoSite()
	if err != nil {
		s.logger.ErrorContext(ctx, fmt.Sprintf("reload geosite fail: %s", err))
		return
	}
	s.codeMap.Store(codeMap)
	s.logger.InfoContext(ctx, fmt.Sprintf("reload geosite success, cost: %s", time.Since(startTime).String()))
}

func (s *SingGeoSite) Match(ctx context.Context, args map[string]any, dnsCtx *adapter.DNSContext) (bool, error) {
	question := dnsCtx.ReqMsg.Question[0]
	switch question.Qtype {
	case dns.TypeA:
	case dns.TypeAAAA:
	case dns.TypeCNAME:
	default:
		return false, nil
	}
	domain := question.Name
	if dns.IsFqdn(domain) {
		domain = strings.Trim(domain, ".")
	}
	codeMap := s.codeMap.Load()
	if codeMap == nil {
		return false, fmt.Errorf("codemap not found")
	}
	codeAnyListAny, ok := args["code"]
	if ok {
		codeAnyList, ok := codeAnyListAny.([]any)
		if ok {
			codeList := make([]string, 0)
			for _, codeAny := range codeAnyList {
				code, ok := codeAny.(string)
				if !ok {
					err := fmt.Errorf("code type error: %T", args["code"])
					s.logger.ErrorContext(ctx, err)
					return false, err
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
							return true, nil
						}
						continue
					} else {
						err := fmt.Errorf("code %s not found", code)
						s.logger.ErrorContext(ctx, err)
						return false, err
					}
				}
			}
			return false, nil
		}
		codeItem, ok := codeAnyListAny.(string)
		if ok {
			dItem, ok := (*codeMap)[codeItem]
			if ok {
				matchType, matchStr, match := dItem.match(ctx, domain)
				if match {
					s.logger.DebugContext(ctx, fmt.Sprintf("match sing-geosite: code ==> %s, type ==> %s, rule ==> %s", codeItem, matchType, matchStr))
					return true, nil
				} else {
					return false, nil
				}
			} else {
				err := fmt.Errorf("code %s not found", codeItem)
				s.logger.ErrorContext(ctx, err)
				return false, err
			}
		}
		err := fmt.Errorf("code type error: %T", args["code"])
		s.logger.ErrorContext(ctx, err)
		return false, err
	}
	for code, dItem := range *codeMap {
		matchType, matchStr, match := dItem.match(ctx, domain)
		if match {
			s.logger.DebugContext(ctx, fmt.Sprintf("match sing-geosite: code ==> %s, type ==> %s, rule ==> %s", code, matchType, matchStr))
			return true, nil
		}
	}
	return false, nil
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
					regex, err := regexp.Compile(item.Value, regexp.RE2)
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
