package upstream

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/upstream"

	"github.com/miekg/dns"
)

type randomUpstream struct {
	tag          string
	logger       log.ContextLogger
	core         adapter.Core
	upstreams    []adapter.Upstream
	upstreamTags []string
}

var _ adapter.Upstream = (*randomUpstream)(nil)

func NewRandomUpstream(logger log.Logger, core adapter.Core, options upstream.UpstreamOption) (adapter.Upstream, error) {
	u := &randomUpstream{
		tag:    options.Tag,
		logger: log.NewContextLogger(log.NewTagLogger(logger, fmt.Sprintf("upstream/%s/%s", constant.UpstreamRandom, options.Tag))),
		core:   core,
	}
	if options.RandomOption.Upstreams == nil || len(options.RandomOption.Upstreams) == 0 {
		return nil, fmt.Errorf("create random upstream: upstreams is empty")
	}
	u.upstreamTags = make([]string, 0)
	for _, tag := range options.RandomOption.Upstreams {
		u.upstreamTags = append(u.upstreamTags, tag)
	}
	return u, nil
}

func (u *randomUpstream) Tag() string {
	return u.tag
}

func (u *randomUpstream) Type() string {
	return constant.UpstreamRandom
}

func (u *randomUpstream) Start() error {
	u.upstreams = make([]adapter.Upstream, 0, len(u.upstreamTags))
	for i, tag := range u.upstreamTags {
		up := u.core.GetUpstream(tag)
		if up == nil {
			return fmt.Errorf("start random upstream: upstream [%s] not found", tag)
		}
		u.upstreams[i] = up
	}
	return nil
}

func (u *randomUpstream) Close() error {
	return nil
}

func (u *randomUpstream) ContextLogger() log.ContextLogger {
	return u.logger
}

func (u *randomUpstream) Exchange(ctx context.Context, dnsMsg *dns.Msg) (*dns.Msg, error) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	upstream := u.upstreams[r.Intn(len(u.upstreams))]
	u.logger.InfoContext(ctx, fmt.Sprintf("forward to %s", upstream.Tag()))
	return upstream.Exchange(ctx, dnsMsg)
}
