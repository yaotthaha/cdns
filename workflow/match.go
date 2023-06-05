package workflow

import (
	"context"
	"fmt"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/workflow"

	"github.com/miekg/dns"
)

type matchItem struct {
	mode       string
	clientIP   []*types.Addr
	qType      []uint16
	qName      []string
	hasRespMsg *bool
	respIP     []*types.Addr
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

	if options.ClientIP != nil && len(options.ClientIP) > 0 {
		rItem.clientIP = make([]*types.Addr, 0, len(options.ClientIP))
		for i, ip := range options.ClientIP {
			rItem.clientIP[i] = ip
		}
	}

	if options.QType != nil && len(options.QType) > 0 {
		rItem.qType = make([]uint16, 0, len(options.QType))
		for i, qType := range options.QType {
			rItem.qType[i] = uint16(qType)
		}
	}

	if options.QName != nil && len(options.QName) > 0 {
		rItem.qName = make([]string, 0, len(options.QName))
		for i, qName := range options.QName {
			rItem.qName[i] = qName
		}
	}

	if options.HasRespMsg != nil {
		rItem.hasRespMsg = options.HasRespMsg
	}

	if options.RespIP != nil && len(options.RespIP) > 0 {
		rItem.respIP = make([]*types.Addr, 0, len(options.RespIP))
		for i, respIP := range options.RespIP {
			rItem.respIP[i] = respIP
		}
	}

	if options.Mark != nil && len(options.Mark) > 0 {
		rItem.mark = make([]uint64, 0, len(options.Mark))
		for i, mark := range options.Mark {
			rItem.mark[i] = mark
		}
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
	}

	if options.MatchOr != nil && len(options.MatchOr) > 0 {
		matchOr := make([]*matchItem, 0, len(options.MatchOr))
		for i, mo := range options.MatchOr {
			rule, err := newMatchItem(core, mo, modeOr)
			if err != nil {
				return nil, err
			}
			matchOr[i] = rule
		}
		rItem.matchOr = matchOr
	}

	if options.MatchAnd != nil && len(options.MatchAnd) > 0 {
		matchAnd := make([]*matchItem, 0, len(options.MatchAnd))
		for i, ma := range options.MatchAnd {
			rule, err := newMatchItem(core, ma, modeAnd)
			if err != nil {
				return nil, err
			}
			matchAnd[i] = rule
		}
		rItem.matchAnd = matchAnd
	}

	return rItem, nil
}

func (r *matchItem) matchClientIP(ctx context.Context, logger log.ContextLogger, dnsCtx *adapter.DNSContext) int {
	if r.respIP != nil {
		for _, cip := range r.clientIP {
			if cip.Compare(dnsCtx.ClientIP.Addr()) == 0 {
				logger.DebugContext(ctx, fmt.Sprintf("match: clientIP: %s", cip.String()))
				return 1
			}
		}
		return 0
	}
	return -1
}

func (r *matchItem) matchQType(ctx context.Context, logger log.ContextLogger, dnsCtx *adapter.DNSContext) int {
	if r.qType != nil {
		for _, qType := range r.qType {
			if qType == dnsCtx.ReqMsg.Question[0].Qtype {
				logger.DebugContext(ctx, fmt.Sprintf("match: qType: %s", dns.TypeToString[qType]))
				return 1
			}
		}
		return 0
	}
	return -1
}

func (r *matchItem) matchQName(ctx context.Context, logger log.ContextLogger, dnsCtx *adapter.DNSContext) int {
	if r.qName != nil {
		for _, qName := range r.qName {
			qName = dns.Fqdn(qName)
			if qName == dnsCtx.ReqMsg.Question[0].Name {
				logger.DebugContext(ctx, fmt.Sprintf("match: qName: %s", qName))
				return 1
			}
		}
		return 0
	}
	return -1
}

func (r *matchItem) matchHasRespMsg(ctx context.Context, logger log.ContextLogger, dnsCtx *adapter.DNSContext) int {
	if r.hasRespMsg != nil {
		if *r.hasRespMsg && dnsCtx.RespMsg != nil {
			logger.DebugContext(ctx, fmt.Sprintf("match: hasRespMsg: %t", *r.hasRespMsg))
			return 1
		}
		if !*r.hasRespMsg && dnsCtx.RespMsg == nil {
			logger.DebugContext(ctx, fmt.Sprintf("match: hasRespMsg: %t", *r.hasRespMsg))
			return 1
		}
		return 0
	}
	return -1
}

func (r *matchItem) matchRespIP(ctx context.Context, logger log.ContextLogger, dnsCtx *adapter.DNSContext) int {
	if r.respIP != nil && dnsCtx.RespMsg != nil {
		return func() int {
			for _, rip := range r.respIP {
				for _, rr := range dnsCtx.RespMsg.Answer {
					switch ans := rr.(type) {
					case *dns.A:
						if rip.String() == ans.A.String() {
							logger.DebugContext(ctx, fmt.Sprintf("match: respIP: %s", rip.String()))
							return 1
						}
					case *dns.AAAA:
						if rip.String() == ans.AAAA.String() {
							logger.DebugContext(ctx, fmt.Sprintf("match: respIP: %s", rip.String()))
							return 1
						}
					}
				}
			}
			return 0
		}()
	}
	return -1
}

func (r *matchItem) matchMark(ctx context.Context, logger log.ContextLogger, dnsCtx *adapter.DNSContext) int {
	if r.mark != nil && dnsCtx.Mark > 0 {
		for _, mark := range r.mark {
			if mark == dnsCtx.Mark {
				logger.DebugContext(ctx, fmt.Sprintf("match: mark ==> %d", mark))
				return 1
			}
		}
		return 0
	}
	return -1
}

func (r *matchItem) matchPlugin(ctx context.Context, logger log.ContextLogger, dnsCtx *adapter.DNSContext) int {
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

func (r *matchItem) matchMatchOr(ctx context.Context, logger log.ContextLogger, dnsCtx *adapter.DNSContext) int {
	if r.matchOr != nil {
		for _, mo := range r.matchOr {
			if mo.match(ctx, logger, dnsCtx) {
				logger.DebugContext(ctx, fmt.Sprintf("match: matchOr"))
				return 1
			}
		}
		return 0
	}
	return -1
}

func (r *matchItem) matchMatchAnd(ctx context.Context, logger log.ContextLogger, dnsCtx *adapter.DNSContext) int {
	if r.matchAnd != nil {
		for _, ma := range r.matchAnd {
			if !ma.match(ctx, logger, dnsCtx) {
				return 0
			}
			logger.DebugContext(ctx, fmt.Sprintf("match: matchAnd"))
		}
		return 1
	}
	return -1
}

type matchItemFunc func(context.Context, log.ContextLogger, *adapter.DNSContext) int

func (r *matchItem) matchItemFuncs() []matchItemFunc {
	return []matchItemFunc{
		r.matchMark,
		r.matchQType,
		r.matchQName,
		r.matchHasRespMsg,
		r.matchRespIP,
		r.matchPlugin,
		r.matchMatchOr,
		r.matchMatchAnd,
	}
}

func (r *matchItem) matchAnd0(ctx context.Context, logger log.ContextLogger, dnsCtx *adapter.DNSContext) bool {
	t := false
	for _, f := range r.matchItemFuncs() {
		result := f(ctx, logger, dnsCtx)
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
	for _, f := range r.matchItemFuncs() {
		result := f(ctx, logger, dnsCtx)
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
