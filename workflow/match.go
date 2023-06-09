package workflow

import (
	"context"
	"fmt"
	"net/netip"
	"os"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/lib/tools"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/workflow"

	"github.com/miekg/dns"
)

const (
	matchTypeListener   = "listener"
	matchTypeClientIP   = "client-ip"
	matchTypeQType      = "qtype"
	matchTypeQName      = "qname"
	matchTypeHasRespMsg = "has-resp-msg"
	matchTypeRespIP     = "resp-ip"
	matchTypeMark       = "mark"
	matchTypeEnv        = "env"
	matchTypeMetadata   = "metadata"
	matchTypePlugin     = "plugin"
	matchTypeMatchOr    = "match-or"
	matchTypeMatchAnd   = "match-and"
)

type matchItem struct {
	listener   []string
	clientIP   []any
	qType      []uint16
	qName      []string
	hasRespMsg *bool
	respIP     []any
	mark       []uint64
	env        map[string]string
	metadata   map[string]string
	plugin     *matchPlugin
	matchOr    []*matchItem
	matchAnd   []*matchItem

	invert    bool
	matchType string
}

type matchPlugin struct {
	plugin adapter.MatchPlugin
	args   map[string]any
}

func newMatchItem(core adapter.Core, options workflow.RuleMatchItem) (*matchItem, error) {
	rItem := &matchItem{
		invert: options.Invert,
	}
	rn := 0

	if options.Listener != nil && len(options.Listener) > 0 {
		rItem.listener = make([]string, len(options.Listener))
		for i, listener := range options.Listener {
			rItem.listener[i] = listener
		}
		rItem.matchType = matchTypeListener
		rn++
	}

	if options.ClientIP != nil && len(options.ClientIP) > 0 {
		rItem.clientIP = make([]any, 0, len(options.ClientIP))
		for _, addrStr := range options.ClientIP {
			ip, err := netip.ParseAddr(addrStr)
			if err == nil {
				rItem.clientIP = append(rItem.clientIP, ip)
				continue
			}
			cidr, err := netip.ParsePrefix(addrStr)
			if err == nil {
				rItem.clientIP = append(rItem.clientIP, cidr)
				continue
			}
			return nil, fmt.Errorf("invalid client-ip %s", addrStr)
		}
		rItem.matchType = matchTypeClientIP
		rn++
	}

	if options.QType != nil && len(options.QType) > 0 {
		rItem.qType = make([]uint16, 0, len(options.QType))
		for _, qType := range options.QType {
			rItem.qType = append(rItem.qType, uint16(qType))
		}
		rItem.matchType = matchTypeQType
		rn++
	}

	if options.QName != nil && len(options.QName) > 0 {
		rItem.qName = make([]string, 0, len(options.QName))
		for _, qName := range options.QName {
			rItem.qName = append(rItem.qName, qName)
		}
		rItem.matchType = matchTypeQName
		rn++
	}

	if options.HasRespMsg != nil {
		rItem.hasRespMsg = options.HasRespMsg
		rItem.matchType = matchTypeHasRespMsg
		rn++
	}

	if options.RespIP != nil && len(options.RespIP) > 0 {
		rItem.respIP = make([]any, 0, len(options.RespIP))
		for _, addrStr := range options.RespIP {
			ip, err := netip.ParseAddr(addrStr)
			if err == nil {
				rItem.respIP = append(rItem.respIP, ip)
				continue
			}
			cidr, err := netip.ParsePrefix(addrStr)
			if err == nil {
				rItem.respIP = append(rItem.respIP, cidr)
				continue
			}
			return nil, fmt.Errorf("invalid resp-ip %s", addrStr)
		}
		rItem.matchType = matchTypeRespIP
		rn++
	}

	if options.Mark != nil && len(options.Mark) > 0 {
		rItem.mark = make([]uint64, len(options.Mark))
		for i, mark := range options.Mark {
			rItem.mark[i] = mark
		}
		rItem.matchType = matchTypeMark
		rn++
	}

	if options.Env != nil && len(options.Env) > 0 {
		rItem.env = make(map[string]string)
		for k, v := range options.Env {
			rItem.env[k] = v
		}
		rItem.matchType = matchTypeEnv
		rn++
	}

	if options.Metadata != nil && len(options.Metadata) > 0 {
		rItem.metadata = make(map[string]string)
		for k, v := range options.Metadata {
			rItem.metadata[k] = v
		}
		rItem.matchType = matchTypeMetadata
		rn++
	}

	if options.Plugin != nil {
		plugin := core.GetMatchPlugin(options.Plugin.Tag)
		if plugin == nil {
			return nil, fmt.Errorf("match plugin %s not found", options.Plugin.Tag)
		}
		matchPlugin := &matchPlugin{
			plugin: plugin,
			args:   options.Plugin.Args,
		}
		rItem.plugin = matchPlugin
		rItem.matchType = matchTypePlugin
		rn++
	}

	if options.MatchOr != nil && len(options.MatchOr) > 0 {
		matchOr := make([]*matchItem, 0, len(options.MatchOr))
		for _, mo := range options.MatchOr {
			rule, err := newMatchItem(core, mo)
			if err != nil {
				return nil, fmt.Errorf("invalid match-or: %+v, err: %s", mo, err)
			}
			matchOr = append(matchOr, rule)
		}
		rItem.matchOr = matchOr
		rItem.matchType = matchTypeMatchOr
		rn++
	}

	if options.MatchAnd != nil && len(options.MatchAnd) > 0 {
		matchAnd := make([]*matchItem, 0, len(options.MatchAnd))
		for _, ma := range options.MatchAnd {
			rule, err := newMatchItem(core, ma)
			if err != nil {
				return nil, fmt.Errorf("invalid match-and: %+v, err: %s", ma, err)
			}
			matchAnd = append(matchAnd, rule)
		}
		rItem.matchAnd = matchAnd
		rItem.matchType = matchTypeMatchAnd
		rn++
	}

	if rn != 1 {
		return nil, fmt.Errorf("invalid match item: just allow one rule")
	}

	return rItem, nil
}

type matchFunc func(ctx context.Context, logger log.ContextLogger, r *matchItem, dnsCtx *adapter.DNSContext) int

func matchListener(ctx context.Context, logger log.ContextLogger, r *matchItem, dnsCtx *adapter.DNSContext) int {
	if r.listener != nil {
		matchStr := ""
		for _, l := range r.listener {
			if l == dnsCtx.Listener {
				matchStr = l
				break
			}
		}
		if matchStr == "" && r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("no match(invert): listener => %s", dnsCtx.Listener))
			return 1
		} else if matchStr != "" && r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("match(invert): listener => %s", matchStr))
			return 0
		} else if matchStr == "" && !r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("no match: listener => %s", dnsCtx.Listener))
			return 0
		} else {
			logger.DebugContext(ctx, fmt.Sprintf("match: listener => %s", matchStr))
			return 1
		}
	}
	return -1
}

func matchClientIP(ctx context.Context, logger log.ContextLogger, r *matchItem, dnsCtx *adapter.DNSContext) int {
	if r.respIP != nil {
		matchStr := ""
		for _, addrAny := range r.clientIP {
			switch addr := addrAny.(type) {
			case netip.Addr:
				if addr.Compare(dnsCtx.ClientIP) == 0 {
					matchStr = addr.String()
					break
				}
				continue
			case netip.Prefix:
				if addr.Contains(dnsCtx.ClientIP) {
					matchStr = addr.String()
					break
				}
				continue
			}
			break
		}
		if matchStr == "" && r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("no match(invert): client-ip => %s", dnsCtx.ClientIP))
			return 1
		} else if matchStr != "" && r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("match(invert): client-ip => %s", matchStr))
			return 0
		} else if matchStr == "" && !r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("no match: client-ip => %s", dnsCtx.ClientIP))
			return 0
		} else {
			logger.DebugContext(ctx, fmt.Sprintf("match: client-ip => %s", matchStr))
			return 1
		}
	}
	return -1
}

func matchQType(ctx context.Context, logger log.ContextLogger, r *matchItem, dnsCtx *adapter.DNSContext) int {
	if r.qType != nil {
		matchStr := ""
		for _, qType := range r.qType {
			if qType == dnsCtx.ReqMsg.Question[0].Qtype {
				matchStr = dns.TypeToString[qType]
				break
			}
		}
		if matchStr == "" && r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("no match(invert): qtype => %s", dns.TypeToString[dnsCtx.ReqMsg.Question[0].Qtype]))
			return 1
		} else if matchStr != "" && r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("match(invert): qtype => %s", matchStr))
			return 0
		} else if matchStr == "" && !r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("no match: qtype => %s", dns.TypeToString[dnsCtx.ReqMsg.Question[0].Qtype]))
			return 0
		} else {
			logger.DebugContext(ctx, fmt.Sprintf("match: qtype => %s", matchStr))
			return 1
		}
	}
	return -1
}

func matchQName(ctx context.Context, logger log.ContextLogger, r *matchItem, dnsCtx *adapter.DNSContext) int {
	if r.qName != nil {
		matchStr := ""
		for _, qName := range r.qName {
			qName = dns.Fqdn(qName)
			if qName == dnsCtx.ReqMsg.Question[0].Name {
				matchStr = qName
				break
			}
		}
		if matchStr == "" && r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("no match(invert): qname => %s", dnsCtx.ReqMsg.Question[0].Name))
			return 1
		} else if matchStr != "" && r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("match(invert): qname => %s", matchStr))
			return 0
		} else if matchStr == "" && !r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("no match: qname => %s", dnsCtx.ReqMsg.Question[0].Name))
			return 0
		} else {
			logger.DebugContext(ctx, fmt.Sprintf("match: qname => %s", matchStr))
			return 1
		}
	}
	return -1
}

func matchHasRespMsg(ctx context.Context, logger log.ContextLogger, r *matchItem, dnsCtx *adapter.DNSContext) int {
	if r.hasRespMsg != nil {
		matchStr := ""
		if *r.hasRespMsg && dnsCtx.RespMsg != nil {
			matchStr = fmt.Sprintf("%t", *r.hasRespMsg)
		}
		if !*r.hasRespMsg && dnsCtx.RespMsg == nil {
			matchStr = fmt.Sprintf("%t", *r.hasRespMsg)
		}
		if matchStr == "" && r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("no match(invert): has-resp-msg => %t", dnsCtx.RespMsg != nil))
			return 1
		} else if matchStr != "" && r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("match(invert): has-resp-msg => %s", matchStr))
			return 0
		} else if matchStr == "" && !r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("no match: has-resp-msg => %t", dnsCtx.RespMsg != nil))
			return 0
		} else {
			logger.DebugContext(ctx, fmt.Sprintf("match: has-resp-msg => %s", matchStr))
			return 1
		}
	}
	return -1
}

func matchRespIP(ctx context.Context, logger log.ContextLogger, r *matchItem, dnsCtx *adapter.DNSContext) int {
	if r.respIP != nil && dnsCtx.RespMsg != nil {
		answerIPs := make([]netip.Addr, 0)
		for _, rr := range dnsCtx.RespMsg.Answer {
			switch r := rr.(type) {
			case *dns.A:
				answerIPs = append(answerIPs, netip.MustParseAddr(r.A.String()))
			case *dns.AAAA:
				answerIPs = append(answerIPs, netip.MustParseAddr(r.AAAA.String()))
			}
		}
		if len(answerIPs) == 0 {
			return -1
		}
		matchStr := ""
		for _, addr := range r.respIP {
			switch addr := addr.(type) {
			case netip.Addr:
				for _, ansIP := range answerIPs {
					if addr.Compare(ansIP) == 0 {
						matchStr = addr.String()
						break
					}
				}
			case netip.Prefix:
				for _, ansIP := range answerIPs {
					if addr.Contains(ansIP) {
						matchStr = addr.String()
						break
					}
				}
			}
		}
		if matchStr == "" && r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("no match(invert): resp-ip => [%s]", tools.Join(answerIPs, ",")))
			return 1
		} else if matchStr != "" && r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("match(invert): resp-ip => %s", matchStr))
			return 0
		} else if matchStr == "" && !r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("no match: resp-ip => [%s]", tools.Join(answerIPs, ",")))
			return 0
		} else {
			logger.DebugContext(ctx, fmt.Sprintf("match: resp-ip => %s", matchStr))
			return 1
		}
	}
	return -1
}

func matchMark(ctx context.Context, logger log.ContextLogger, r *matchItem, dnsCtx *adapter.DNSContext) int {
	if r.mark != nil && dnsCtx.Mark > 0 {
		matchStr := ""
		for _, mark := range r.mark {
			if mark == dnsCtx.Mark {
				matchStr = fmt.Sprintf("%d", mark)
				break
			}
		}
		if matchStr == "" && r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("no match(invert): mark => %d", dnsCtx.Mark))
			return 1
		} else if matchStr != "" && r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("match(invert): mark => %s", matchStr))
			return 0
		} else if matchStr == "" && !r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("no match: mark => %d", dnsCtx.Mark))
			return 0
		} else {
			logger.DebugContext(ctx, fmt.Sprintf("match: mark => %s", matchStr))
			return 1
		}
	}
	return -1
}

func matchEnv(ctx context.Context, logger log.ContextLogger, r *matchItem, _ *adapter.DNSContext) int {
	if r.env != nil {
		match := true
		for k := range r.env {
			v := os.Getenv(k)
			if r.env[k] != v {
				match = false
				break
			}
		}
		if !match && r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("no match(invert): env => %s", r.env))
			return 1
		} else if match && r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("match(invert): env => %s", r.env))
			return 0
		} else if !match && !r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("no match: env => %s", r.env))
			return 0
		} else {
			logger.DebugContext(ctx, fmt.Sprintf("match: env => %s", r.env))
			return 1
		}
	}
	return -1
}

func matchMetaData(ctx context.Context, logger log.ContextLogger, r *matchItem, dnsCtx *adapter.DNSContext) int {
	if r.metadata != nil && dnsCtx.MetaData.Len() > 0 {
		match := true
		for k := range r.metadata {
			vAny, ok := dnsCtx.MetaData.Load("user-" + k)
			var v string
			if ok {
				v = vAny.Value().(string)
			}
			if !ok || r.metadata[k] != v {
				match = false
				break
			}
		}
		if !match && r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("no match(invert): metadata => %s", r.metadata))
			return 1
		} else if match && r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("match(invert): metadata => %s", r.metadata))
			return 0
		} else if !match && !r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("no match: metadata => %s", r.metadata))
			return 0
		} else {
			logger.DebugContext(ctx, fmt.Sprintf("match: metadata => %s", r.metadata))
			return 1
		}
	}
	return -1
}

func matchPluginFunc(ctx context.Context, logger log.ContextLogger, r *matchItem, dnsCtx *adapter.DNSContext) int {
	if r.plugin != nil {
		result, err := r.plugin.plugin.Match(ctx, r.plugin.args, dnsCtx)
		if err != nil {
			return -1
		}
		if result && r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("match(invert): plugin [%s], args: %+v", r.plugin.plugin.Tag(), r.plugin.args))
			return 0
		} else if !result && r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("no match(invert): plugin [%s], args: %+v", r.plugin.plugin.Tag(), r.plugin.args))
			return 1
		} else if result && !r.invert {
			logger.DebugContext(ctx, fmt.Sprintf("match: plugin [%s], args: %+v", r.plugin.plugin.Tag(), r.plugin.args))
			return 1
		} else {
			logger.DebugContext(ctx, fmt.Sprintf("no match: plugin [%s], args: %+v", r.plugin.plugin.Tag(), r.plugin.args))
			return 0
		}
	}
	return -1
}

func matchMatchOr(ctx context.Context, logger log.ContextLogger, r *matchItem, dnsCtx *adapter.DNSContext) int {
	if r.matchOr != nil {
		result := func() bool {
			for _, mo := range r.matchOr {
				if mo.match(ctx, logger, dnsCtx) {
					return true
				}
			}
			return false
		}()
		if result && r.invert {
			logger.DebugContext(ctx, "match(invert): match-or")
			return 0
		} else if !result && r.invert {
			logger.DebugContext(ctx, "no match(invert): match-or")
			return 1
		} else if result && !r.invert {
			logger.DebugContext(ctx, "match: match-or")
			return 1
		} else {
			logger.DebugContext(ctx, "no match: match-or")
			return 0
		}
	}
	return -1
}

func matchMatchAnd(ctx context.Context, logger log.ContextLogger, r *matchItem, dnsCtx *adapter.DNSContext) int {
	if r.matchAnd != nil {
		result := func() bool {
			if len(r.matchAnd) > 0 {
				for _, ma := range r.matchAnd {
					if !ma.match(ctx, logger, dnsCtx) {
						return false
					}
				}
				return true
			}
			return false
		}()
		if result && r.invert {
			logger.DebugContext(ctx, "match(invert): match-or")
			return 0
		} else if !result && r.invert {
			logger.DebugContext(ctx, "no match(invert): match-or")
			return 1
		} else if result && !r.invert {
			logger.DebugContext(ctx, "match: match-or")
			return 1
		} else {
			logger.DebugContext(ctx, "no match: match-or")
			return 0
		}
	}
	return -1
}

func (r *matchItem) match(ctx context.Context, logger log.ContextLogger, dnsCtx *adapter.DNSContext) bool {
	var f matchFunc
	switch r.matchType {
	case matchTypeListener:
		f = matchListener
	case matchTypeClientIP:
		f = matchClientIP
	case matchTypeQType:
		f = matchQType
	case matchTypeQName:
		f = matchQName
	case matchTypeHasRespMsg:
		f = matchHasRespMsg
	case matchTypeRespIP:
		f = matchRespIP
	case matchTypeMark:
		f = matchMark
	case matchTypeEnv:
		f = matchEnv
	case matchTypeMetadata:
		f = matchMetaData
	case matchTypePlugin:
		f = matchPluginFunc
	case matchTypeMatchOr:
		f = matchMatchOr
	case matchTypeMatchAnd:
		f = matchMatchAnd
	default:
		logger.ErrorContext(ctx, fmt.Sprintf("unknown match type: %s", r.matchType))
		return false
	}
	result := f(ctx, logger, r, dnsCtx)
	if result >= 0 {
		if result == 1 {
			return true
		}
		return false
	}
	return false
}
