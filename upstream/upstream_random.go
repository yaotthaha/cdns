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
	tag    string
	logger log.ContextLogger

	core adapter.Core

	upstreams    []adapter.Upstream
	upstreamTags []string
}

var _ adapter.Upstream = (*randomUpstream)(nil)

func NewRandomUpstream(rootLogger log.Logger, options upstream.UpstreamOptions) (adapter.Upstream, error) {
	u := &randomUpstream{
		tag:    options.Tag,
		logger: log.NewContextLogger(log.NewTagLogger(rootLogger, fmt.Sprintf("upstream/%s", options.Tag))),
	}
	if options.Options == nil {
		return nil, fmt.Errorf("create random upstream fail: options is empty")
	}
	randomOptions := options.Options.(*upstream.UpstreamRandomOptions)
	if randomOptions.Upstreams == nil || len(randomOptions.Upstreams) == 0 {
		return nil, fmt.Errorf("create random upstream fail: upstreams is empty")
	}
	u.upstreamTags = make([]string, 0)
	for _, tag := range randomOptions.Upstreams {
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

func (u *randomUpstream) WithCore(core adapter.Core) {
	u.core = core
}

func (u *randomUpstream) Start() error {
	u.upstreams = make([]adapter.Upstream, 0)
	for _, tag := range u.upstreamTags {
		up := u.core.GetUpstream(tag)
		if up == nil {
			return fmt.Errorf("start random upstream fail: upstream [%s] not found", tag)
		}
		u.upstreams = append(u.upstreams, up)
	}
	return nil
}

func (u *randomUpstream) ContextLogger() log.ContextLogger {
	return u.logger
}

func (u *randomUpstream) Exchange(ctx context.Context, dnsMsg *dns.Msg) (*dns.Msg, error) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	up := u.upstreams[r.Intn(len(u.upstreams))]
	u.logger.InfoContext(ctx, fmt.Sprintf("forward to %s", up.Tag()))
	return up.Exchange(ctx, dnsMsg)
}
