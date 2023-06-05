package domain

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/log"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

const PluginType = "domain"

func init() {
	adapter.RegisterMatchPlugin(PluginType, NewDomain)
}

var _ adapter.MatchPlugin = (*Domain)(nil)

type Domain struct {
	tag      string
	logger   log.ContextLogger
	full     []string
	suffix   []string
	keyword  []string
	regex    []*regexp.Regexp
	fileList []string
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

	optionBytes, err := yaml.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("parse args fail: %s", err)
	}
	var op option
	err = yaml.Unmarshal(optionBytes, &op)
	if err != nil {
		return nil, fmt.Errorf("parse args fail: %s", err)
	}
	var hasRule bool
	if op.Full != nil && len(op.Full) > 0 {
		d.full = op.Full
		hasRule = true
	}
	if op.Suffix != nil && len(op.Suffix) > 0 {
		d.suffix = op.Suffix
		hasRule = true
	}
	if op.Keyword != nil && len(op.Keyword) > 0 {
		d.keyword = op.Keyword
		hasRule = true
	}
	if op.Regex != nil && len(op.Regex) > 0 {
		regexs := make([]*regexp.Regexp, 0, len(op.Regex))
		for i, r := range op.Regex {
			regex, err := regexp.Compile(r)
			if err != nil {
				return nil, fmt.Errorf("invalid regex: %s", err)
			}
			regexs[i] = regex
		}
		d.regex = regexs
		hasRule = true
	}
	if op.File != nil && len(op.File) > 0 {
		d.fileList = op.File
		hasRule = true
	}
	if !hasRule {
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
		for _, filename := range d.fileList {
			d.logger.Info(fmt.Sprintf("loading domain file: %s", filename))
			ruleItem, err := d.readRules(filename)
			if err != nil {
				return err
			}
			if ruleItem.full != nil && len(ruleItem.full) > 0 {
				if d.full == nil {
					d.full = make([]string, 0)
				}
				d.full = append(d.full, ruleItem.full...)
			}
			if ruleItem.suffix != nil && len(ruleItem.suffix) > 0 {
				if d.suffix == nil {
					d.suffix = make([]string, 0)
				}
				d.suffix = append(d.suffix, ruleItem.suffix...)
			}
			if ruleItem.keyword != nil && len(ruleItem.keyword) > 0 {
				if d.keyword == nil {
					d.keyword = make([]string, 0)
				}
				d.keyword = append(d.keyword, ruleItem.keyword...)
			}
			if ruleItem.regex != nil && len(ruleItem.regex) > 0 {
				if d.regex == nil {
					d.regex = make([]*regexp.Regexp, 0)
				}
				d.regex = append(d.regex, ruleItem.regex...)
			}
			d.logger.Info(fmt.Sprintf("load domain file: %s success", filename))
		}
	}
	var (
		fullN    int
		suffixN  int
		keywordN int
		regexN   int
	)
	if d.full != nil {
		fullN = len(d.full)
	}
	if d.suffix != nil {
		suffixN = len(d.suffix)
	}
	if d.keyword != nil {
		keywordN = len(d.keyword)
	}
	if d.regex != nil {
		regexN = len(d.regex)
	}
	d.logger.Info(fmt.Sprintf("domain rule: full: %d, suffix: %d, keyword: %d, regex: %d", fullN, suffixN, keywordN, regexN))
	return nil
}

func (d *Domain) Close() error {
	return nil
}

func (d *Domain) WithContext(ctx context.Context) {
}

func (d *Domain) WithLogger(logger log.Logger) {
	d.logger = log.NewContextLogger(log.NewTagLogger(logger, fmt.Sprintf("match-plugin/%s/%s", PluginType, d.tag)))
}

func (d *Domain) Match(ctx context.Context, m map[string]any, dnsCtx *adapter.DNSContext) bool {
	if d.full != nil {
		for _, domain := range d.full {
			fqdn := dns.Fqdn(domain)
			if dnsCtx.ReqMsg.Question[0].Name == fqdn {
				d.logger.DebugContext(ctx, fmt.Sprintf("match domain_full ==> %s", domain))
				return true
			}
		}
	}
	if d.suffix != nil {
		for _, domain := range d.suffix {
			fqdn := dns.Fqdn(domain)
			if strings.HasSuffix(dnsCtx.ReqMsg.Question[0].Name, fqdn) {
				d.logger.DebugContext(ctx, fmt.Sprintf("match domain_suffix ==> %s", domain))
				return true
			}
		}
	}
	if d.keyword != nil {
		for _, domain := range d.keyword {
			fqdn := dns.Fqdn(domain)
			if strings.Contains(dnsCtx.ReqMsg.Question[0].Name, fqdn) {
				d.logger.DebugContext(ctx, fmt.Sprintf("match domain_keyword ==> %s", domain))
				return true
			}
		}
	}
	if d.regex != nil {
		for _, regex := range d.regex {
			if regex.MatchString(dnsCtx.ReqMsg.Question[0].Name) {
				d.logger.DebugContext(ctx, fmt.Sprintf("match domain_regex ==> %s", regex.String()))
				return true
			}
		}
	}
	return false
}

type ruleItem struct {
	full    []string
	suffix  []string
	keyword []string
	regex   []*regexp.Regexp
}

func (d *Domain) readRules(filename string) (*ruleItem, error) {
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
		switch {
		case strings.HasPrefix(line, "full:"):
			ruleItem.full = append(ruleItem.full, strings.TrimSpace(strings.TrimPrefix(line, "full:")))
		case strings.HasPrefix(line, "suffix:"):
			ruleItem.suffix = append(ruleItem.suffix, strings.TrimSpace(strings.TrimPrefix(line, "suffix:")))
		case strings.HasPrefix(line, "keyword:"):
			ruleItem.keyword = append(ruleItem.keyword, strings.TrimSpace(strings.TrimPrefix(line, "keyword:")))
		case strings.HasPrefix(line, "regex:"):
			re, err := regexp.Compile(strings.TrimSpace(strings.TrimPrefix(line, "regex:")))
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
