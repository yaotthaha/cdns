package upstream

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/upstream"

	"github.com/miekg/dns"
)

type queryTestUpstream struct {
	ctx    context.Context
	tag    string
	logger log.ContextLogger

	core adapter.Core

	upstreams    []adapter.Upstream
	upstreamTags []string
	upstreamMap  map[adapter.Upstream]*atomic.Pointer[testResult]

	fallback     bool
	testInterval time.Duration
	testDomain   string
	testLock     sync.Mutex
}

const (
	testInterval = 10 * time.Second
	testDomain   = "www.example.com"
)

var _ adapter.Upstream = (*queryTestUpstream)(nil)

func NewQueryTestUpstream(ctx context.Context, rootLogger log.Logger, options upstream.UpstreamOptions) (adapter.Upstream, error) {
	f := &queryTestUpstream{
		ctx:    ctx,
		logger: log.NewContextLogger(log.NewTagLogger(rootLogger, fmt.Sprintf("upstream/%s", options.Tag))),
		tag:    options.Tag,
	}
	if options.Options == nil {
		return nil, fmt.Errorf("create querytest upstream fail: options is empty")
	}
	querytestOptions := options.Options.(*upstream.UpstreamQueryTestOptions)
	if querytestOptions.Upstreams == nil || len(querytestOptions.Upstreams) == 0 {
		return nil, fmt.Errorf("create querytest upstream fail: upstreams is empty")
	}
	f.upstreamTags = make([]string, 0)
	for _, tag := range querytestOptions.Upstreams {
		f.upstreamTags = append(f.upstreamTags, tag)
	}
	if querytestOptions.TestInterval > 0 {
		f.testInterval = time.Duration(querytestOptions.TestInterval)
	} else {
		f.testInterval = testInterval
	}
	if querytestOptions.TestDomain != "" {
		f.testDomain = querytestOptions.TestDomain
	} else {
		f.testDomain = testDomain
	}
	f.fallback = querytestOptions.Fallback
	return f, nil
}

func (u *queryTestUpstream) Tag() string {
	return u.tag
}

func (u *queryTestUpstream) Type() string {
	return constant.UpstreamQueryTest
}

func (u *queryTestUpstream) WithCore(core adapter.Core) {
	u.core = core
}

func (u *queryTestUpstream) Start() error {
	u.upstreams = make([]adapter.Upstream, 0)
	u.upstreamMap = make(map[adapter.Upstream]*atomic.Pointer[testResult])
	for _, tag := range u.upstreamTags {
		up := u.core.GetUpstream(tag)
		if up == nil {
			return fmt.Errorf("start querytest upstream fail: upstream [%s] not found", tag)
		}
		u.upstreams = append(u.upstreams, up)
		u.upstreamMap[up] = new(atomic.Pointer[testResult])
	}
	u.test()
	go u.keepTest()
	return nil
}

func (u *queryTestUpstream) ContextLogger() log.ContextLogger {
	return u.logger
}

func (u *queryTestUpstream) Exchange(ctx context.Context, dnsMsg *dns.Msg) (*dns.Msg, error) {
	up := u.getBestUpstream()
	u.logger.InfoContext(ctx, fmt.Sprintf("forward to %s", up.Tag()))
	return up.Exchange(ctx, dnsMsg)
}

func (u *queryTestUpstream) test() {
	if !u.testLock.TryLock() {
		return
	}
	defer u.testLock.Unlock()
	wg := sync.WaitGroup{}
	for up, p := range u.upstreamMap {
		wg.Add(1)
		go func(upstream adapter.Upstream, p *atomic.Pointer[testResult]) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(u.ctx, constant.DNSQueryTimeout)
			defer cancel()
			upstream.ContextLogger().Debug(fmt.Sprintf("querytest upstream [%s] test", u.tag))
			start := time.Now()
			_, err := upstream.Exchange(ctx, u.newDNSMsg())
			delay := time.Since(start)
			if err == nil {
				p.Store(&testResult{
					time:  start,
					delay: delay,
				})
			} else {
				p.Store(nil)
			}
		}(up, p)
	}
	wg.Wait()
}

func (u *queryTestUpstream) keepTest() {
	ticker := time.NewTicker(u.testInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			u.test()
		case <-u.ctx.Done():
			return
		}
	}
}

func (u *queryTestUpstream) getBestUpstream() adapter.Upstream {
	var (
		minDelay     time.Duration
		bestUpstream adapter.Upstream
	)
	for _, up := range u.upstreams {
		test := u.upstreamMap[up].Load()
		if test == nil {
			continue
		}
		if minDelay == 0 || test.delay < minDelay {
			minDelay = test.delay
			bestUpstream = up
			if u.fallback {
				break
			}
		}
	}
	if bestUpstream == nil {
		bestUpstream = u.upstreams[0]
	}
	return bestUpstream
}

type testResult struct {
	time  time.Time
	delay time.Duration
}

func (u *queryTestUpstream) newDNSMsg() *dns.Msg {
	d := new(dns.Msg)
	d.SetQuestion(dns.Fqdn(u.testDomain), dns.TypeA)
	return d
}
