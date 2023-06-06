package workflow

import (
	"context"
	"fmt"
	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/workflow"
	"net/netip"

	"github.com/miekg/dns"
)

type matchItem struct {
	mode       string
	listener   []string
	clientIP   []any
	qType      []uint16
	qName      []string
	hasRespMsg *bool
	respIP     []any
	mark       []uint64
	plugin     *matchPlugin
	matchOr    []*matchItem
	matchAnd   []*matchItem
	invert     bool
}

type matchPlugin struct {
	plugin adapter.MatchPlugin
	args   map[string]any
}

func newMatchItem(core adapter.Core, options workflow.RuleMatchItem, mode string) (*matchItem, error) {
	rItem := &matchItem{
		mode:   mode,
		invert: options.Invert,
	}
	rn := 0

	if options.Listener != nil && len(options.Listener) > 0 {
		rItem.listener = make([]string, len(options.Listener))
		for i, listener := range options.Listener {
			rItem.listener[i] = listener
		}
		rn++
	}

	if options.ClientIP != nil && len(options.ClientIP) > 0 {
		rItem.clientIP = make([]any, len(options.ClientIP))
		for i, addrStr := range options.ClientIP {
			ip, err := netip.ParseAddr(addrStr)
			if err == nil {
				rItem.clientIP[i] = ip
				continue
			}
			cidr, err := netip.ParsePrefix(addrStr)
			if err == nil {
				rItem.clientIP = append(rItem.clientIP, cidr)
				continue
			}
			return nil, fmt.Errorf("invalid client_ip %s", addrStr)
		}
		rn++
	}

	if options.QType != nil && len(options.QType) > 0 {
		rItem.qType = make([]uint16, len(options.QType))
		for i, qType := range options.QType {
			rItem.qType[i] = uint16(qType)
		}
		rn++
	}

	if options.QName != nil && len(options.QName) > 0 {
		rItem.qName = make([]string, len(options.QName))
		for i, qName := range options.QName {
			rItem.qName[i] = qName
		}
		rn++
	}

	if options.HasRespMsg != nil {
		rItem.hasRespMsg = options.HasRespMsg
		rn++
	}

	if options.RespIP != nil && len(options.RespIP) > 0 {
		rItem.respIP = make([]any, len(options.RespIP))
		for i, addrStr := range options.RespIP {
			ip, err := netip.ParseAddr(addrStr)
			if err == nil {
				rItem.respIP[i] = ip
				continue
			}
			cidr, err := netip.ParsePrefix(addrStr)
			if err == nil {
				rItem.respIP[i] = cidr
				continue
			}
			return nil, fmt.Errorf("invalid resp_ip %s", addrStr)
		}
		rn++
	}

	if options.Mark != nil && len(options.Mark) > 0 {
		rItem.mark = make([]uint64, len(options.Mark))
		for i, mark := range options.Mark {
			rItem.mark[i] = mark
		}
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
		rn++
	}

	if options.MatchOr != nil && len(options.MatchOr) > 0 {
		matchOr := make([]*matchItem, len(options.MatchOr))
		for i, mo := range options.MatchOr {
			rule, err := newMatchItem(core, mo, modeOr)
			if err != nil {
				return nil, fmt.Errorf("invalid match_or: %+v, err: %s", mo, err)
			}
			matchOr[i] = rule
		}
		rItem.matchOr = matchOr
		rn++
	}

	if options.MatchAnd != nil && len(options.MatchAnd) > 0 {
		matchAnd := make([]*matchItem, len(options.MatchAnd))
		for i, ma := range options.MatchAnd {
			rule, err := newMatchItem(core, ma, modeAnd)
			if err != nil {
				return nil, fmt.Errorf("invalid match_and: %+v, err: %s", ma, err)
			}
			matchAnd[i] = rule
		}
		rItem.matchAnd = matchAnd
		rn++
	}

	if rn == 0 {
		if mode == modeOr {
			return nil, fmt.Errorf("invalid match_or: no rule")
		} else if mode == modeAnd {
			return nil, fmt.Errorf("invalid match_and: no rule")
		} else {
			return nil, fmt.Errorf("invalid rule: no rule")
		}
	}
	if rn > 1 {
		if mode == modeOr {
			return nil, fmt.Errorf("invalid match_or: more than one rule")
		} else if mode == modeAnd {
			return nil, fmt.Errorf("invalid match_and: more than one rule")
		} else {
			return nil, fmt.Errorf("invalid rule: more than one rule")
		}
	}

	return rItem, nil
}

func matchListener(ctx context.Context, logger log.ContextLogger, r *matchItem, dnsCtx *adapter.DNSContext) int {
	if r.listener != nil {
		for _, l := range r.listener {
			if l == dnsCtx.Listener {
				logger.DebugContext(ctx, fmt.Sprintf("match: listener => %s", l))
				return 1
			}
		}
		return 0
	}
	return -1
}

func matchClientIP(ctx context.Context, logger log.ContextLogger, r *matchItem, dnsCtx *adapter.DNSContext) int {
	if r.respIP != nil {
		for _, addrAny := range r.clientIP {
			switch addr := addrAny.(type) {
			case netip.Addr:
				if addr.Compare(dnsCtx.ClientIP.Addr()) == 0 {
					logger.DebugContext(ctx, fmt.Sprintf("match: client_ip => %s", addr.String()))
					return 1
				}
			case netip.Prefix:
				if addr.Contains(dnsCtx.ClientIP.Addr()) {
					logger.DebugContext(ctx, fmt.Sprintf("match: client_ip => %s", addr.String()))
					return 1
				}
			}
		}
		return 0
	}
	return -1
}

func matchQType(ctx context.Context, logger log.ContextLogger, r *matchItem, dnsCtx *adapter.DNSContext) int {
	if r.qType != nil {
		for _, qType := range r.qType {
			if qType == dnsCtx.ReqMsg.Question[0].Qtype {
				logger.DebugContext(ctx, fmt.Sprintf("match: qtype => %s", dns.TypeToString[qType]))
				return 1
			}
		}
		return 0
	}
	return -1
}

func matchQName(ctx context.Context, logger log.ContextLogger, r *matchItem, dnsCtx *adapter.DNSContext) int {
	if r.qName != nil {
		for _, qName := range r.qName {
			qName = dns.Fqdn(qName)
			if qName == dnsCtx.ReqMsg.Question[0].Name {
				logger.DebugContext(ctx, fmt.Sprintf("match: qname => %s", qName))
				return 1
			}
		}
		return 0
	}
	return -1
}

func matchHasRespMsg(ctx context.Context, logger log.ContextLogger, r *matchItem, dnsCtx *adapter.DNSContext) int {
	if r.hasRespMsg != nil {
		if *r.hasRespMsg && dnsCtx.RespMsg != nil {
			logger.DebugContext(ctx, fmt.Sprintf("match: hasRespMsg => %t", *r.hasRespMsg))
			return 1
		}
		if !*r.hasRespMsg && dnsCtx.RespMsg == nil {
			logger.DebugContext(ctx, fmt.Sprintf("match: hasRespMsg => %t", *r.hasRespMsg))
			return 1
		}
		return 0
	}
	return -1
}

func matchRespIP(ctx context.Context, logger log.ContextLogger, r *matchItem, dnsCtx *adapter.DNSContext) int {
	if r.respIP != nil && dnsCtx.RespMsg != nil {
		return func() int {
			for _, addrAny := range r.respIP {
				for _, rr := range dnsCtx.RespMsg.Answer {
					switch ans := rr.(type) {
					case *dns.A:
						switch addr := addrAny.(type) {
						case netip.Addr:
							if addr.String() == ans.A.String() {
								logger.DebugContext(ctx, fmt.Sprintf("match: resp_ip => %s", addr.String()))
								return 1
							}
						case netip.Prefix:
							ansIP, err := netip.ParseAddr(ans.A.String())
							if err != nil {
								continue
							}
							if addr.Contains(ansIP) {
								logger.DebugContext(ctx, fmt.Sprintf("match: resp_ip => %s", addr.String()))
								return 1
							}
						}
					case *dns.AAAA:
						switch addr := addrAny.(type) {
						case netip.Addr:
							if addr.String() == ans.AAAA.String() {
								logger.DebugContext(ctx, fmt.Sprintf("match: resp_ip => %s", addr.String()))
								return 1
							}
						case netip.Prefix:
							ansIP, err := netip.ParseAddr(ans.AAAA.String())
							if err != nil {
								continue
							}
							if addr.Contains(ansIP) {
								logger.DebugContext(ctx, fmt.Sprintf("match: resp_ip => %s", addr.String()))
								return 1
							}
						}
					}
				}
			}
			return 0
		}()
	}
	return -1
}

func matchMark(ctx context.Context, logger log.ContextLogger, r *matchItem, dnsCtx *adapter.DNSContext) int {
	if r.mark != nil && dnsCtx.Mark > 0 {
		for _, mark := range r.mark {
			if mark == dnsCtx.Mark {
				logger.DebugContext(ctx, fmt.Sprintf("match: mark => %d", mark))
				return 1
			}
		}
		return 0
	}
	return -1
}

func matchPluginFunc(ctx context.Context, logger log.ContextLogger, r *matchItem, dnsCtx *adapter.DNSContext) int {
	if r.plugin != nil {
		result := r.plugin.plugin.Match(ctx, r.plugin.args, dnsCtx)
		if result {
			logger.DebugContext(ctx, fmt.Sprintf("match: plugin [%s]", r.plugin.plugin.Tag()))
			return 1
		}
		return 0
	}
	return -1
}

func matchMatchOr(ctx context.Context, logger log.ContextLogger, r *matchItem, dnsCtx *adapter.DNSContext) int {
	if r.matchOr != nil {
		for _, mo := range r.matchOr {
			if mo.match(ctx, logger, dnsCtx) {
				logger.DebugContext(ctx, fmt.Sprintf("match: match_or => %+v", mo))
				return 1
			}
		}
		return 0
	}
	return -1
}

func matchMatchAnd(ctx context.Context, logger log.ContextLogger, r *matchItem, dnsCtx *adapter.DNSContext) int {
	if r.matchAnd != nil {
		for _, ma := range r.matchAnd {
			if !ma.match(ctx, logger, dnsCtx) {
				return 0
			}
			logger.DebugContext(ctx, fmt.Sprintf("match: match_and => %+v", ma))
		}
		return 1
	}
	return -1
}

type matchItemFunc func(context.Context, log.ContextLogger, *matchItem, *adapter.DNSContext) int

func matchItemFuncs() []matchItemFunc {
	return []matchItemFunc{
		matchMark,
		matchQType,
		matchQName,
		matchHasRespMsg,
		matchListener,
		matchRespIP,
		matchPluginFunc,
		matchMatchOr,
		matchMatchAnd,
	}
}

func (r *matchItem) matchAnd0(ctx context.Context, logger log.ContextLogger, dnsCtx *adapter.DNSContext) bool {
	t := false
	for _, f := range matchItemFuncs() {
		result := f(ctx, logger, r, dnsCtx)
		if result >= 0 {
			switch {
			case result == 1 && !r.invert:
				t = true
				continue
			case result == 1 && r.invert:
				logger.DebugContext(ctx, fmt.Sprintf("match invert"))
				return false
			case result == 0 && !r.invert:
				return false
			case result == 0 && r.invert:
				logger.DebugContext(ctx, fmt.Sprintf("match invert"))
				t = true
				continue
			}
		}
	}
	return t
}

func (r *matchItem) matchOr0(ctx context.Context, logger log.ContextLogger, dnsCtx *adapter.DNSContext) bool {
	t := false
	for _, f := range matchItemFuncs() {
		result := f(ctx, logger, r, dnsCtx)
		if result >= 0 {
			switch {
			case result == 1 && !r.invert:
				return true
			case result == 1 && r.invert:
				logger.DebugContext(ctx, fmt.Sprintf("match invert"))
				t = true
				continue
			case result == 0 && !r.invert:
				continue
			case result == 0 && r.invert:
				logger.DebugContext(ctx, fmt.Sprintf("match invert"))
				t = true
				return true
			}
		}
	}
	return t
}

func (r *matchItem) match(ctx context.Context, logger log.ContextLogger, dnsCtx *adapter.DNSContext) bool {
	switch r.mode {
	case modeAnd:
		return r.matchAnd0(ctx, logger, dnsCtx)
	case modeOr:
		return r.matchOr0(ctx, logger, dnsCtx)
	}
	return false
}
