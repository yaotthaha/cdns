package upstream

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/upstream"

	"github.com/miekg/dns"
)

type multiUpstream struct {
	ctx          context.Context
	tag          string
	logger       log.ContextLogger
	core         adapter.Core
	upstreams    []adapter.Upstream
	upstreamTags []string
}

var _ adapter.Upstream = (*multiUpstream)(nil)

func NewMultiUpstream(ctx context.Context, logger log.Logger, core adapter.Core, options upstream.UpstreamOption) (adapter.Upstream, error) {
	u := &multiUpstream{
		ctx:    ctx,
		tag:    options.Tag,
		logger: log.NewContextLogger(log.NewTagLogger(logger, fmt.Sprintf("upstream/%s", options.Tag))),
		core:   core,
	}
	if options.MultiOption.Upstreams == nil || len(options.MultiOption.Upstreams) == 0 {
		return nil, fmt.Errorf("create multi upstream fail: upstreams is empty")
	}
	u.upstreamTags = make([]string, 0)
	for _, tag := range options.MultiOption.Upstreams {
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

func (u *multiUpstream) Close() error {
	return nil
}

func (u *multiUpstream) ContextLogger() log.ContextLogger {
	return u.logger
}

func (u *multiUpstream) Exchange(ctx context.Context, dnsMsg *dns.Msg) (*dns.Msg, error) {
	wg := sync.WaitGroup{}
	resultChan := make(chan *dns.Msg, 1)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	u.logger.InfoContext(ctx, fmt.Sprintf("multi forward to [%s]", strings.Join(u.upstreamTags, ", ")))
	for _, up := range u.upstreams {
		wg.Add(1)
		go func(upstream adapter.Upstream) {
			defer wg.Done()
			u.logger.InfoContext(ctx, fmt.Sprintf("multi forward to %s", upstream.Tag()))
			respMsg, err := upstream.Exchange(ctx, dnsMsg)
			if err == nil {
				select {
				case resultChan <- respMsg:
				default:
				}
			}
		}(up)
	}
	var respMsg *dns.Msg
	select {
	case respMsg = <-resultChan:
	case <-ctx.Done():
	case <-u.ctx.Done():
		return nil, context.Canceled
	}
	cancel()
	wg.Wait()
	if respMsg == nil {
		return nil, context.Canceled
	}
	return respMsg, nil
}
