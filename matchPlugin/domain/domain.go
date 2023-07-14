package domain

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/log"

	regexp "github.com/dlclark/regexp2"
	"github.com/go-chi/chi"
	"github.com/miekg/dns"
	"github.com/mitchellh/mapstructure"
)

const PluginType = "domain"

func init() {
	adapter.RegisterMatchPlugin(PluginType, NewDomain)
}

var (
	_ adapter.MatchPlugin       = (*Domain)(nil)
	_ adapter.Starter           = (*Domain)(nil)
	_ adapter.WithContextLogger = (*Domain)(nil)
	_ adapter.APIHandler        = (*Domain)(nil)
)

type Domain struct {
	tag        string
	logger     log.ContextLogger
	reloadLock sync.Mutex
	insideRule atomic.Pointer[rule]
	fileList   []string
	fileRule   atomic.Pointer[rule]
}

type option struct {
	Full    types.Listable[string] `yaml:"full"`
	Suffix  types.Listable[string] `yaml:"suffix"`
	Keyword types.Listable[string] `yaml:"keyword"`
	Regex   types.Listable[string] `yaml:"regex"`
	File    types.Listable[string] `yaml:"file"`
}

func NewDomain(tag string, args map[string]any) (adapter.MatchPlugin, error) {
	d := &Domain{
		tag: tag,
	}

	var op option
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.UnmarshalInterfaceHookFunc(),
		Result:     &op,
	})
	if err != nil {
		return nil, fmt.Errorf("decode config fail: %s", err)
	}
	err = decoder.Decode(args)
	if err != nil {
		return nil, fmt.Errorf("decode config fail: %s", err)
	}
	insideRule := &rule{}
	var hasRule int
	if op.Full != nil && len(op.Full) > 0 {
		fulls := make([]string, len(op.Full))
		for i, f := range op.Full {
			fulls[i] = f
		}
		if len(fulls) > 0 {
			insideRule.full = fulls
			hasRule++
		}
	}
	if op.Suffix != nil && len(op.Suffix) > 0 {
		suffixs := make([]string, len(op.Suffix))
		for i, f := range op.Suffix {
			suffixs[i] = f
		}
		if len(suffixs) > 0 {
			insideRule.suffix = suffixs
			hasRule++
		}
	}
	if op.Keyword != nil && len(op.Keyword) > 0 {
		keywords := make([]string, len(op.Keyword))
		for i, f := range op.Keyword {
			keywords[i] = f
		}
		if len(keywords) > 0 {
			insideRule.keyword = keywords
			hasRule++
		}
	}
	if op.Regex != nil && len(op.Regex) > 0 {
		regexs := make([]*regexp.Regexp, len(op.Regex))
		for i, r := range op.Regex {
			regex, err := regexp.Compile(r, regexp.RE2)
			if err != nil {
				return nil, fmt.Errorf("parse keyword domain %s fail: %s", r, err)
			}
			regexs[i] = regex
		}
		if len(regexs) > 0 {
			insideRule.regex = regexs
			hasRule++
		}
	}
	if hasRule > 0 {
		d.insideRule.Store(insideRule)
	}
	if op.File != nil && len(op.File) > 0 {
		d.fileList = op.File
		hasRule++
	}
	if hasRule == 0 {
		return nil, fmt.Errorf("invalid args: no rule")
	}
	return d, nil
}

func (d *Domain) Tag() string {
	return d.tag
}

func (d *Domain) Type() string {
	return PluginType
}

func (d *Domain) Start() error {
	if d.fileList != nil {
		rules := make([]*rule, 0)
		for _, filename := range d.fileList {
			d.logger.Info(fmt.Sprintf("loading domain file: %s", filename))
			ruleItem, err := readRules(filename)
			if err != nil {
				return err
			}
			rules = append(rules, ruleItem)
			d.logger.Info(fmt.Sprintf("load domain file: %s success", filename))
		}
		fileRule := mergeRule(rules...)
		var (
			fullN    int
			suffixN  int
			keywordN int
			regexN   int
		)
		fullN, suffixN, keywordN, regexN = fileRule.length()
		d.logger.Info(fmt.Sprintf("file domain rule: full: %d, suffix: %d, keyword: %d, regex: %d", fullN, suffixN, keywordN, regexN))
		d.fileRule.Store(fileRule)
	}
	if insideRule := d.insideRule.Load(); insideRule != nil {
		var (
			fullN    int
			suffixN  int
			keywordN int
			regexN   int
		)
		fullN, suffixN, keywordN, regexN = insideRule.length()
		d.logger.Info(fmt.Sprintf("inside domain rule: full: %d, suffix: %d, keyword: %d, regex: %d", fullN, suffixN, keywordN, regexN))
	}
	return nil
}

func (d *Domain) WithContextLogger(contextLogger log.ContextLogger) {
	d.logger = contextLogger
}

func (d *Domain) APIHandler() http.Handler {
	r := chi.NewRouter()
	r.Get("/reload", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		go d.reloadFileRule(r.Context())
	})
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	return r
}

func (d *Domain) reloadFileRule(ctx context.Context) {
	if !d.reloadLock.TryLock() {
		return
	}
	defer d.reloadLock.Unlock()
	startTime := time.Now()
	d.logger.InfoContext(ctx, "reload file rule...")
	if d.fileList != nil {
		files := make([]*rule, 0)
		for _, f := range d.fileList {
			rule, err := readRules(f)
			if err != nil {
				d.logger.ErrorContext(ctx, fmt.Sprintf("reload file rule fail, file %s, err: %s", f, err))
				return
			}
			files = append(files, rule)
		}
		fileRule := mergeRule(files...)
		var (
			fullN    int
			suffixN  int
			keywordN int
			regexN   int
		)
		fullN, suffixN, keywordN, regexN = fileRule.length()
		d.logger.InfoContext(ctx, fmt.Sprintf("file domain rule: full: %d, suffix: %d, keyword: %d, regex: %d", fullN, suffixN, keywordN, regexN))
		d.fileRule.Store(fileRule)
		d.logger.InfoContext(ctx, "reload file rule success, cost: %s", time.Since(startTime).String())
	} else {
		d.logger.InfoContext(ctx, "no file to reload")
	}
}

func (d *Domain) Match(ctx context.Context, _ map[string]any, dnsCtx *adapter.DNSContext) (bool, error) {
	insideRule := d.insideRule.Load()
	if insideRule != nil {
		matchType, matchRule, match := insideRule.match(ctx, dnsCtx.ReqMsg.Question[0].Name)
		if match {
			d.logger.DebugContext(ctx, fmt.Sprintf("match %s ==> %s", matchType, matchRule))
			return true, nil
		}
	}
	select {
	case <-ctx.Done():
		return false, context.Canceled
	default:
	}
	fileRule := d.fileRule.Load()
	if fileRule != nil {
		matchType, matchRule, match := fileRule.match(ctx, dnsCtx.ReqMsg.Question[0].Name)
		if match {
			d.logger.DebugContext(ctx, fmt.Sprintf("match %s ==> %s", matchType, matchRule))
			return true, nil
		}
	}
	return false, nil
}

type rule struct {
	full    []string
	suffix  []string
	keyword []string
	regex   []*regexp.Regexp
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
		switch {
		case strings.HasPrefix(line, "full:"):
			ruleItem.full = append(ruleItem.full, strings.TrimSpace(strings.TrimPrefix(line, "full:")))
		case strings.HasPrefix(line, "suffix:"):
			ruleItem.suffix = append(ruleItem.suffix, strings.TrimSpace(strings.TrimPrefix(line, "suffix:")))
		case strings.HasPrefix(line, "keyword:"):
			ruleItem.keyword = append(ruleItem.keyword, strings.TrimSpace(strings.TrimPrefix(line, "keyword:")))
		case strings.HasPrefix(line, "regex:"):
			re, err := regexp.Compile(strings.TrimSpace(strings.TrimPrefix(line, "regex:")), regexp.RE2)
			if err != nil {
				return nil, err
			}
			ruleItem.regex = append(ruleItem.regex, re)
		default:
			return nil, fmt.Errorf("invalid rule: %s", line)
		}
	}
	return ruleItem, nil
}

func mergeRule(rules ...*rule) *rule {
	merge := &rule{}
	for _, r := range rules {
		if r.full != nil {
			merge.full = append(merge.full, r.full...)
		}
		if r.suffix != nil {
			merge.suffix = append(merge.suffix, r.suffix...)
		}
		if r.keyword != nil {
			merge.keyword = append(merge.keyword, r.keyword...)
		}
		if r.regex != nil {
			merge.regex = append(merge.regex, r.regex...)
		}
	}
	return merge
}

func (r *rule) match(ctx context.Context, matchDomain string) (string, string, bool) {
	if r.full != nil {
		for _, domain := range r.full {
			select {
			case <-ctx.Done():
				return "", "", false
			default:
			}
			fqdn := dns.Fqdn(domain)
			if matchDomain == fqdn {
				return "domain_full", domain, true
			}
		}
	}
	if r.suffix != nil {
		for _, domain := range r.suffix {
			select {
			case <-ctx.Done():
				return "", "", false
			default:
			}
			fqdn := dns.Fqdn(domain)
			if strings.HasSuffix(matchDomain, fqdn) {
				return "domain_suffix", domain, true
			}
		}
	}
	if r.keyword != nil {
		for _, domain := range r.keyword {
			select {
			case <-ctx.Done():
				return "", "", false
			default:
			}
			fqdn := dns.Fqdn(domain)
			if strings.Contains(matchDomain, fqdn) {
				return "domain_keyword", domain, true
			}
		}
	}
	if r.regex != nil {
		for _, regex := range r.regex {
			select {
			case <-ctx.Done():
				return "", "", false
			default:
			}
			if match, err := regex.MatchString(matchDomain); err == nil && match {
				return "domain_regex", regex.String(), true
			}
		}
	}
	return "", "", false
}

func (r *rule) length() (int, int, int, int) {
	var (
		fullN    int
		suffixN  int
		keywordN int
		regexN   int
	)
	if r.full != nil {
		fullN = len(r.full)
	}
	if r.suffix != nil {
		suffixN = len(r.suffix)
	}
	if r.keyword != nil {
		keywordN = len(r.keyword)
	}
	if r.regex != nil {
		regexN = len(r.regex)
	}
	return fullN, suffixN, keywordN, regexN
}
