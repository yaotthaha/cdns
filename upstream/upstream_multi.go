package upstream

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/upstream"

	"github.com/miekg/dns"
)

type multiUpstream struct {
	ctx    context.Context
	tag    string
	logger log.ContextLogger

	core adapter.Core

	upstreams    []adapter.Upstream
	upstreamTags []string
}

var (
	_ adapter.Upstream                       = (*multiUpstream)(nil)
	_ adapter.UpstreamExchangeWithDNSContext = (*multiUpstream)(nil)
	_ adapter.Starter                        = (*multiUpstream)(nil)
	_ adapter.WithCore                       = (*multiUpstream)(nil)
)

func NewMultiUpstream(ctx context.Context, logger log.ContextLogger, options upstream.UpstreamOptions) (adapter.Upstream, error) {
	u := &multiUpstream{
		ctx:    ctx,
		tag:    options.Tag,
		logger: logger,
	}
	if options.Options == nil {
		return nil, fmt.Errorf("create multi upstream fail: options is empty")
	}
	multiOptions := options.Options.(*upstream.UpstreamMultiOptions)
	if multiOptions.Upstreams == nil || len(multiOptions.Upstreams) == 0 {
		return nil, fmt.Errorf("create multi upstream fail: upstreams is empty")
	}
	u.upstreamTags = make([]string, 0)
	for _, tag := range multiOptions.Upstreams {
		u.upstreamTags = append(u.upstreamTags, tag)
	}
	return u, nil
}

func (u *multiUpstream) Tag() string {
	return u.tag
}

func (u *multiUpstream) Type() string {
	return constant.UpstreamMulti
}

func (u *multiUpstream) WithCore(core adapter.Core) {
	u.core = core
}

func (u *multiUpstream) Dependencies() []string {
	return u.upstreamTags
}

func (u *multiUpstream) Start() error {
	u.upstreams = make([]adapter.Upstream, 0)
	for _, tag := range u.upstreamTags {
		up := u.core.GetUpstream(tag)
		if up == nil {
			return fmt.Errorf("start multi upstream fail: upstream [%s] not found", tag)
		}
		u.upstreams = append(u.upstreams, up)
	}
	return nil
}

func (u *multiUpstream) ContextLogger() log.ContextLogger {
	return u.logger
}

func (u *multiUpstream) Exchange(ctx context.Context, dnsMsg *dns.Msg) (*dns.Msg, error) {
	wg := sync.WaitGroup{}
	var saveResult atomic.Pointer[dns.Msg]
	var saveErr types.AtomicValue[error]
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	u.logger.DebugContext(ctx, fmt.Sprintf("multi forward to [%s]", strings.Join(u.upstreamTags, ", ")))
	for _, up := range u.upstreams {
		wg.Add(1)
		go func(upstream adapter.Upstream) {
			defer wg.Done()
			u.logger.DebugContext(ctx, fmt.Sprintf("multi forward to %s", upstream.Tag()))
			respMsg, err := upstream.Exchange(ctx, dnsMsg)
			if err == nil {
				saveResult.CompareAndSwap(nil, respMsg)
				cancel()
			} else {
				saveErr.CompareAndSwap(nil, err)
			}
		}(up)
	}
	go func() {
		wg.Wait()
		cancel()
	}()
	<-ctx.Done()
	respMsg := saveResult.Load()
	if respMsg != nil {
		return respMsg, nil
	}
	err := saveErr.Load()
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = fmt.Errorf("unknown error")
	}
	return nil, err
}

func (u *multiUpstream) ExchangeWithDNSContext(ctx context.Context, dnsMsg *dns.Msg, dnsCtx *adapter.DNSContext) (*dns.Msg, error) {
	wg := sync.WaitGroup{}
	var saveResult atomic.Pointer[dns.Msg]
	var saveErr types.AtomicValue[error]
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	u.logger.DebugContext(ctx, fmt.Sprintf("multi forward to [%s]", strings.Join(u.upstreamTags, ", ")))
	for _, up := range u.upstreams {
		wg.Add(1)
		go func(upstream adapter.Upstream) {
			defer wg.Done()
			u.logger.DebugContext(ctx, fmt.Sprintf("multi forward to %s", upstream.Tag()))
			respMsg, err := Exchange(ctx, upstream, dnsCtx, dnsMsg)
			if err == nil {
				saveResult.CompareAndSwap(nil, respMsg)
				cancel()
			} else {
				saveErr.CompareAndSwap(nil, err)
			}
		}(up)
	}
	go func() {
		wg.Wait()
		cancel()
	}()
	<-ctx.Done()
	respMsg := saveResult.Load()
	if respMsg != nil {
		return respMsg, nil
	}
	err := saveErr.Load()
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = fmt.Errorf("unknown error")
	}
	return nil, err
}
