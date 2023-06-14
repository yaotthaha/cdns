package upstream

import (
	"context"
	"fmt"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/upstream"

	"github.com/miekg/dns"
)

func NewUpstream(ctx context.Context, core adapter.Core, logger log.Logger, options upstream.UpstreamOption) (adapter.Upstream, error) {
	switch options.Type {
	case constant.UpstreamUDP:
		return NewUDPUpstream(ctx, logger, options)
	case constant.UpstreamTCP:
		return NewTCPUpstream(ctx, logger, options)
	case constant.UpstreamTLS:
		return NewTLSUpstream(ctx, logger, options)
	case constant.UpstreamHTTPS:
		return NewHTTPSUpstream(ctx, logger, options)
	case constant.UpstreamQUIC:
		return NewQUICUpstream(ctx, logger, options)
	case constant.UpstreamRandom:
		return NewRandomUpstream(logger, core, options)
	case constant.UpstreamMulti:
		return NewMultiUpstream(ctx, logger, core, options)
	case constant.UpstreamQueryTest:
		return NewQueryTestUpstream(ctx, logger, core, options)
	default:
		return nil, fmt.Errorf("upstream type %s not supported", options.Type)
	}
}

func RetryUpstream(ctx context.Context, upstream adapter.Upstream, dnsMsg *dns.Msg, dnsCtx *adapter.DNSContext) (*dns.Msg, error) {
	for i := 0; i < 3; i++ {
		startTime := time.Now()
		resp, err := upstream.Exchange(ctx, dnsMsg)
		if err == nil {
			if dnsCtx != nil {
				dnsCtx.SetKV("upstream-time-consuming-"+upstream.Tag(), time.Since(startTime))
			}
			return resp, nil
		}
		upstream.ContextLogger().WarnContext(ctx, fmt.Sprintf("retry %d: %s", i+1, logDNSMsg(dnsMsg)))
	}
	if dnsCtx != nil {
		dnsCtx.SetKV("upstream-time-consuming-"+upstream.Tag(), time.Duration(-1))
	}
	err := fmt.Errorf("retry upstream failed: %s", logDNSMsg(dnsMsg))
	upstream.ContextLogger().ErrorContext(ctx, err.Error())
	return nil, err
}

func logDNSMsg(dnsMsg *dns.Msg) string {
	return fmt.Sprintf("qtype: %s, qname: %s", dns.TypeToString[dnsMsg.Question[0].Qtype], dnsMsg.Question[0].Name)
}
