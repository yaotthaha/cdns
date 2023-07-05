package bootstrap

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/option/upstream"

	"github.com/miekg/dns"
)

const (
	IPv4Prefer = "ipv4-prefer"
	IPv6Prefer = "ipv6-prefer"
	IPv4Only   = "ipv4-only"
	IPv6Only   = "ipv6-only"
)

type Core interface {
	GetUpstream(string) adapter.Upstream
}

type Bootstrap struct {
	upstreamTag string
	core        Core
	upstream    adapter.Upstream
	strategy    string
	cache       types.AtomicValue[*result]
}

type result struct {
	ips      []netip.Addr
	deadline time.Time
}

func NewBootstrap(options upstream.BootstrapOptions) (*Bootstrap, error) {
	switch options.Strategy {
	case "", IPv4Prefer:
		options.Strategy = IPv4Prefer
	case IPv6Prefer:
	case IPv4Only:
	case IPv6Only:
	default:
		return nil, fmt.Errorf("strategy %s not supported", options.Strategy)
	}
	return &Bootstrap{
		upstreamTag: options.Upstream,
		strategy:    options.Strategy,
	}, nil
}

func (b *Bootstrap) WithCore(core Core) {
	b.core = core
}

func (b *Bootstrap) Start() error {
	up := b.core.GetUpstream(b.upstreamTag)
	if up == nil {
		return fmt.Errorf("upstream %s not found", b.upstreamTag)
	}
	b.upstream = up
	return nil
}

func (b *Bootstrap) query0(ctx context.Context, dnsMsg *dns.Msg) (*result, error) {
	respMsg, err := b.upstream.Exchange(ctx, dnsMsg)
	if err != nil {
		return nil, err
	}
	minTTL := time.Duration(0)
	ips := make([]netip.Addr, 0)
	for _, answer := range respMsg.Answer {
		ttl := time.Duration(answer.Header().Ttl) * time.Second
		if minTTL == 0 || ttl < minTTL {
			minTTL = ttl
		}
		switch ans := answer.(type) {
		case *dns.A:
			ip, ok := netip.AddrFromSlice(ans.A)
			if ok {
				ips = append(ips, ip)
			}
		case *dns.AAAA:
			ip, ok := netip.AddrFromSlice(ans.AAAA)
			if ok {
				ips = append(ips, ip)
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no ip found")
	}
	return &result{
		ips:      ips,
		deadline: time.Now().Add(minTTL),
	}, nil
}

func (b *Bootstrap) queryA(ctx context.Context, domain string) (*result, error) {
	dnsMsg := &dns.Msg{}
	dnsMsg.SetQuestion(domain, dns.TypeA)
	return b.query0(ctx, dnsMsg)
}

func (b *Bootstrap) queryAAAA(ctx context.Context, domain string) (*result, error) {
	dnsMsg := &dns.Msg{}
	dnsMsg.SetQuestion(domain, dns.TypeAAAA)
	return b.query0(ctx, dnsMsg)
}

func (b *Bootstrap) queryWrapper(ctx context.Context, domain string) (*result, error) {
	if b.strategy == IPv4Only {
		return b.queryA(ctx, domain)
	}
	if b.strategy == IPv6Only {
		return b.queryAAAA(ctx, domain)
	}
	resCh := make(chan *result, 2)
	defer close(resCh)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		res, err := b.queryA(ctx, domain)
		if err != nil {
			return
		}
		resCh <- res
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		res, err := b.queryAAAA(ctx, domain)
		if err != nil {
			return
		}
		resCh <- res
	}()
	wg.Wait()
	var (
		minDeadline time.Time
		ip4         *result
		ip6         *result
	)
	for {
		select {
		case res := <-resCh:
			if res.ips[0].Is4() {
				ip4 = res
			}
			if res.ips[0].Is6() {
				ip6 = res
			}
			continue
		default:
		}
		break
	}
	ips := make([]netip.Addr, 0)
	if b.strategy == IPv4Prefer {
		ips = append(ips, ip4.ips...)
		ips = append(ips, ip6.ips...)
		if ip4.deadline.Before(ip6.deadline) {
			minDeadline = ip4.deadline
		} else {
			minDeadline = ip6.deadline
		}
	}
	if b.strategy == IPv6Prefer {
		ips = append(ips, ip6.ips...)
		ips = append(ips, ip4.ips...)
		if ip6.deadline.Before(ip4.deadline) {
			minDeadline = ip6.deadline
		} else {
			minDeadline = ip4.deadline
		}
	}
	return &result{
		ips:      ips,
		deadline: minDeadline,
	}, nil
}

func (b *Bootstrap) Query(ctx context.Context, domain string) ([]netip.Addr, error) {
	c := b.cache.Load()
	if c != nil {
		if time.Now().Before(c.deadline) {
			return c.ips, nil
		}
		b.cache.CompareAndSwap(c, nil)
	}
	res, err := b.queryWrapper(ctx, domain)
	if err != nil {
		return nil, err
	}
	b.cache.Store(res)
	return res.ips, nil
}

func (b *Bootstrap) QueryAddress(ctx context.Context, domain string, port uint16) ([]string, error) {
	ips, err := b.Query(ctx, domain)
	if err != nil {
		return nil, err
	}
	addresses := make([]string, 0)
	for _, ip := range ips {
		addresses = append(addresses, net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
	}
	return addresses, nil
}
