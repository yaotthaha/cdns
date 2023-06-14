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
	ctx          context.Context
	tag          string
	logger       log.ContextLogger
	core         adapter.Core
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

func NewQueryTestUpstream(ctx context.Context, logger log.Logger, core adapter.Core, options upstream.UpstreamOption) (adapter.Upstream, error) {
	f := &queryTestUpstream{
		ctx:    ctx,
		logger: log.NewContextLogger(log.NewTagLogger(logger, fmt.Sprintf("upstream/%s", options.Tag))),
		core:   core,
		tag:    options.Tag,
	}
	if options.QueryTestOption.Upstreams == nil || len(options.QueryTestOption.Upstreams) == 0 {
		return nil, fmt.Errorf("create querytest upstream fail: upstreams is empty")
	}
	f.upstreamTags = make([]string, 0)
	for _, tag := range options.QueryTestOption.Upstreams {
		f.upstreamTags = append(f.upstreamTags, tag)
	}
	if options.QueryTestOption.TestInterval > 0 {
		f.testInterval = time.Duration(options.QueryTestOption.TestInterval)
	} else {
		f.testInterval = testInterval
	}
	if options.QueryTestOption.TestDomain != "" {
		f.testDomain = options.QueryTestOption.TestDomain
	} else {
		f.testDomain = testDomain
	}
	f.fallback = options.QueryTestOption.Fallback
	return f, nil
}

func (f *queryTestUpstream) Tag() string {
	return f.tag
}

func (f *queryTestUpstream) Type() string {
	return constant.UpstreamQueryTest
}

func (f *queryTestUpstream) Start() error {
	f.upstreams = make([]adapter.Upstream, 0)
	f.upstreamMap = make(map[adapter.Upstream]*atomic.Pointer[testResult])
	for _, tag := range f.upstreamTags {
		up := f.core.GetUpstream(tag)
		if up == nil {
			return fmt.Errorf("start querytest upstream fail: upstream [%s] not found", tag)
		}
		f.upstreams = append(f.upstreams, up)
		f.upstreamMap[up] = new(atomic.Pointer[testResult])
	}
	f.test()
	go f.keepTest()
	return nil
}

func (f *queryTestUpstream) Close() error {
	return nil
}

func (f *queryTestUpstream) ContextLogger() log.ContextLogger {
	return f.logger
}

func (f *queryTestUpstream) Exchange(ctx context.Context, dnsMsg *dns.Msg) (*dns.Msg, error) {
	up := f.getBestUpstream()
	f.logger.InfoContext(ctx, fmt.Sprintf("forward to %s", up.Tag()))
	return up.Exchange(ctx, dnsMsg)
}

func (f *queryTestUpstream) test() {
	if !f.testLock.TryLock() {
		return
	}
	defer f.testLock.Unlock()
	wg := sync.WaitGroup{}
	for u, p := range f.upstreamMap {
		wg.Add(1)
		go func(upstream adapter.Upstream, p *atomic.Pointer[testResult]) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(f.ctx, constant.DNSQueryTimeout)
			defer cancel()
			upstream.ContextLogger().Debug(fmt.Sprintf("querytest upstream [%s] test", f.tag))
			start := time.Now()
			_, err := upstream.Exchange(ctx, f.newDNSMsg())
			delay := time.Since(start)
			if err == nil {
				p.Store(&testResult{
					time:  start,
					delay: delay,
				})
			} else {
				p.Store(nil)
			}
		}(u, p)
	}
	wg.Wait()
}

func (f *queryTestUpstream) keepTest() {
	ticker := time.NewTicker(f.testInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			f.test()
		case <-f.ctx.Done():
			return
		}
	}
}

func (f *queryTestUpstream) getBestUpstream() adapter.Upstream {
	var (
		minDelay     time.Duration
		bestUpstream adapter.Upstream
	)
	for _, u := range f.upstreams {
		test := f.upstreamMap[u].Load()
		if test == nil {
			continue
		}
		if minDelay == 0 || test.delay < minDelay {
			minDelay = test.delay
			bestUpstream = u
			if f.fallback {
				break
			}
		}
	}
	if bestUpstream == nil {
		bestUpstream = f.upstreams[0]
	}
	return bestUpstream
}

type testResult struct {
	time  time.Time
	delay time.Duration
}

func (f *queryTestUpstream) newDNSMsg() *dns.Msg {
	d := new(dns.Msg)
	d.SetQuestion(dns.Fqdn(f.testDomain), dns.TypeA)
	return d
}
