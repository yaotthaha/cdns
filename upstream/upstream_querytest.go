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
	core   adapter.Core

	closedChan chan struct{}

	upstreams    []adapter.Upstream
	upstreamTags []string
	upstreamMap  map[adapter.Upstream]*atomic.Pointer[testResult]

	fallback     bool
	testInterval time.Duration
	testDomain   string
	testLock     sync.Mutex
}

type testResult struct {
	time  time.Time
	delay time.Duration
}

const (
	testInterval = 10 * time.Second
	testDomain   = "www.example.com"
)

var (
	_ adapter.Upstream = (*queryTestUpstream)(nil)
	_ adapter.Starter  = (*queryTestUpstream)(nil)
	_ adapter.WithCore = (*queryTestUpstream)(nil)
)

func NewQueryTestUpstream(ctx context.Context, logger log.ContextLogger, options upstream.UpstreamOptions) (adapter.Upstream, error) {
	f := &queryTestUpstream{
		ctx:    ctx,
		tag:    options.Tag,
		logger: logger,
	}
	if options.QueryTestOptions == nil {
		return nil, fmt.Errorf("create querytest upstream fail: options is empty")
	}
	querytestOptions := options.QueryTestOptions
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

func (u *queryTestUpstream) Dependencies() []string {
	return u.upstreamTags
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
	u.closedChan = make(chan struct{}, 1)
	go u.keepTest()
	return nil
}

func (u *queryTestUpstream) Close() error {
	<-u.closedChan
	close(u.closedChan)
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

func (u *queryTestUpstream) ExchangeWithDNSContext(ctx context.Context, dnsMsg *dns.Msg, dnsCtx *adapter.DNSContext) (*dns.Msg, error) {
	up := u.getBestUpstream()
	u.logger.InfoContext(ctx, fmt.Sprintf("forward to %s", up.Tag()))
	return Exchange(ctx, up, dnsCtx, dnsMsg)
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
			d := new(dns.Msg)
			d.SetQuestion(dns.Fqdn(u.testDomain), dns.TypeA)
			_, err := upstream.Exchange(ctx, d)
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
	defer func() {
		u.closedChan <- struct{}{}
	}()
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

func (u *queryTestUpstream) IsUpstreamGroup() {}

func (u *queryTestUpstream) NowUpstream() adapter.Upstream {
	return u.getBestUpstream()
}

func (u *queryTestUpstream) AllUpstreams() []adapter.Upstream {
	return u.upstreams
}
