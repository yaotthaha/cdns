package ipset

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/execPlugin/ipset/internal"
	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/log"

	"github.com/go-chi/chi"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

var (
	_ adapter.ExecPlugin        = (*IPSet)(nil)
	_ adapter.Starter           = (*IPSet)(nil)
	_ adapter.Closer            = (*IPSet)(nil)
	_ adapter.WithContextLogger = (*IPSet)(nil)
	_ adapter.APIHandler        = (*IPSet)(nil)
)

const PluginType = "ipset"

func init() {
	adapter.RegisterExecPlugin(PluginType, NewIPSet)
}

type IPSet struct {
	tag       string
	logger    log.ContextLogger
	option    option
	flushLock sync.Mutex
	ipset4    internal.IPSet
	ipset6    internal.IPSet
}

type option struct {
	Name4 string             `yaml:"name4"`
	Mask4 uint8              `yaml:"mask4"`
	TTL4  types.TimeDuration `yaml:"ttl4"`
	Name6 string             `yaml:"name6"`
	Mask6 uint8              `yaml:"mask6"`
	TTL6  types.TimeDuration `yaml:"ttl6"`
}

func NewIPSet(tag string, args map[string]any) (adapter.ExecPlugin, error) {
	i := &IPSet{
		tag: tag,
	}

	optionBytes, err := yaml.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("parse args fail: %s", err)
	}
	err = yaml.Unmarshal(optionBytes, &i.option)
	if err != nil {
		return nil, fmt.Errorf("parse args fail: %s", err)
	}
	if i.option.Name4 == "" && i.option.Name6 == "" {
		return nil, fmt.Errorf("empty args")
	}
	if i.option.Mask4 == 0 {
		i.option.Mask4 = 32
	}
	if i.option.Mask6 == 0 {
		i.option.Mask6 = 128
	}
	if i.option.TTL4 == 0 {
		i.option.TTL4 = types.TimeDuration(2 * time.Hour)
	}
	if i.option.TTL6 == 0 {
		i.option.TTL6 = types.TimeDuration(2 * time.Hour)
	}

	return i, nil
}

func (i *IPSet) Tag() string {
	return i.tag
}

func (i *IPSet) Type() string {
	return PluginType
}

func (i *IPSet) Start() error {
	if i.option.Name4 != "" {
		ipset4, err := internal.New(i.option.Name4, internal.Inet4, time.Duration(i.option.TTL4))
		if err != nil {
			return fmt.Errorf("create ipset4 fail: %s", err)
		}
		i.ipset4 = ipset4
	}
	if i.option.Name6 != "" {
		ipset6, err := internal.New(i.option.Name6, internal.Inet6, time.Duration(i.option.TTL6))
		if err != nil {
			return fmt.Errorf("create ipset6 fail: %s", err)
		}
		i.ipset6 = ipset6
	}
	return nil
}

func (i *IPSet) Close() error {
	if i.ipset4 != nil {
		err := i.ipset4.Close()
		if err != nil {
			return fmt.Errorf("close ipset4 conn fail: %s", err)
		}
	}
	if i.ipset6 != nil {
		err := i.ipset6.Close()
		if err != nil {
			return fmt.Errorf("close ipset6 conn fail: %s", err)
		}
	}
	return nil
}

func (i *IPSet) WithContextLogger(contextLogger log.ContextLogger) {
	i.logger = contextLogger
}

func (i *IPSet) APIHandler() http.Handler {
	c := chi.NewRouter()
	c.Get("/flush/all", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		go i.flushAll(r.Context(), true, true)
	})
	c.Get("/flush/4", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		go i.flushAll(r.Context(), true, false)
	})
	c.Get("/flush/6", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		go i.flushAll(r.Context(), false, true)
	})
	return c
}

func (i *IPSet) flushAll(ctx context.Context, inet4, inet6 bool) {
	if i.ipset4 == nil && i.ipset6 == nil {
		return
	}
	if !i.flushLock.TryLock() {
		return
	}
	defer i.flushLock.Unlock()
	if inet4 && i.ipset4 != nil {
		if i.ipset4 != nil {
			i.logger.InfoContext(ctx, "flush all ipset4")
			err := i.ipset4.FlushAll()
			if err != nil {
				i.logger.ErrorContext(ctx, "flush all ipset4 fail: %s", err)
			}
		}
	}
	if inet6 && i.ipset6 != nil {
		i.logger.InfoContext(ctx, "flush all ipset6")
		err := i.ipset6.FlushAll()
		if err != nil {
			i.logger.ErrorContext(ctx, "flush all ipset6 fail: %s", err)
		}
	}
}

type dnsAddrRR struct {
	addr netip.Addr
	ttl  time.Duration // second
}

func (i *IPSet) Exec(ctx context.Context, _ map[string]any, dnsCtx *adapter.DNSContext) bool {
	respMsg := dnsCtx.RespMsg
	if respMsg == nil {
		return true
	}
	var (
		ip4 []dnsAddrRR
		ip6 []dnsAddrRR
	)
	for _, rr := range respMsg.Answer {
		switch r := rr.(type) {
		case *dns.A:
			ip, err := netip.ParseAddr(r.A.String())
			if err != nil {
				i.logger.ErrorContext(ctx, fmt.Sprintf("parse ip %s fail: %s", r.A.String(), err))
				continue
			}
			ip4 = append(ip4, dnsAddrRR{
				addr: ip,
				ttl:  time.Duration(rr.Header().Ttl) * time.Second,
			})
		case *dns.AAAA:
			ip, err := netip.ParseAddr(r.AAAA.String())
			if err != nil {
				i.logger.ErrorContext(ctx, fmt.Sprintf("parse ip %s fail: %s", r.AAAA.String(), err))
				continue
			}
			ip6 = append(ip6, dnsAddrRR{
				addr: ip,
				ttl:  time.Duration(rr.Header().Ttl) * time.Second,
			})
		}
	}
	if len(ip4) == 0 && len(ip6) == 0 {
		return true
	}
	if i.ipset4 != nil && len(ip4) > 0 {
		for _, rr := range ip4 {
			ttl := rr.ttl
			if i.option.TTL4 > 0 {
				ttl = time.Duration(i.option.TTL4)
			}
			prefix := netip.PrefixFrom(rr.addr, int(i.option.Mask4)).Masked()
			err := i.ipset4.AddCIDR(prefix, ttl)
			if err != nil {
				i.logger.ErrorContext(ctx, fmt.Sprintf("add addr %s to %s fail: %s", prefix.String(), i.ipset4.Name(), err))
			} else {
				i.logger.DebugContext(ctx, fmt.Sprintf("add addr %s to %s, ttl: %s", prefix.String(), i.ipset4.Name(), ttl.String()))
			}
		}
	}
	if i.ipset6 != nil && len(ip6) > 0 {
		for _, rr := range ip6 {
			ttl := rr.ttl
			if i.option.TTL6 > 0 {
				ttl = time.Duration(i.option.TTL6)
			}
			prefix := netip.PrefixFrom(rr.addr, int(i.option.Mask6))
			err := i.ipset6.AddCIDR(prefix, ttl)
			if err != nil {
				i.logger.ErrorContext(ctx, fmt.Sprintf("add addr %s to %s fail: %s", prefix.String(), i.ipset6.Name(), err))
			} else {
				i.logger.DebugContext(ctx, fmt.Sprintf("add addr %s to %s, ttl: %s", prefix.String(), i.ipset6.Name(), ttl.String()))
			}
		}
	}
	return true
}
