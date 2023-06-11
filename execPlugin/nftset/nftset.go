package nftset

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/execPlugin/nftset/internal"
	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/log"

	"github.com/go-chi/chi"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

var _ adapter.ExecPlugin = (*NftSet)(nil)

const PluginType = "nftset"

func init() {
	adapter.RegisterExecPlugin(PluginType, NewNftSet)
}

type NftSet struct {
	tag       string
	logger    log.ContextLogger
	option    option
	flushLock sync.Mutex
	nftset4   internal.NftSet
	nftset6   internal.NftSet
}

type option struct {
	TableName4 string             `yaml:"table_name4"`
	SetName4   string             `yaml:"set_name4"`
	Mask4      uint8              `yaml:"mask4"`
	TTL4       types.TimeDuration `yaml:"ttl4"`
	TableName6 string             `yaml:"table_name6"`
	SetName6   string             `yaml:"set_name6"`
	Mask6      uint8              `yaml:"mask6"`
	TTL6       types.TimeDuration `yaml:"ttl6"`
}

func NewNftSet(tag string, args map[string]any) (adapter.ExecPlugin, error) {
	n := &NftSet{
		tag: tag,
	}

	optionBytes, err := yaml.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("parse args fail: %s", err)
	}
	err = yaml.Unmarshal(optionBytes, &n.option)
	if err != nil {
		return nil, fmt.Errorf("parse args fail: %s", err)
	}
	var h bool
	if n.option.TableName4 != "" && n.option.SetName4 != "" {
		h = true
	}
	if n.option.TableName6 != "" && n.option.SetName6 != "" {
		h = true
	}
	if !h {
		return nil, fmt.Errorf("empty args")
	}

	return n, nil
}

func (n *NftSet) Tag() string {
	return n.tag
}

func (n *NftSet) Type() string {
	return PluginType
}

func (n *NftSet) Start() error {
	if n.option.TableName4 != "" && n.option.SetName4 != "" {
		nftset4, err := internal.New(n.option.TableName4, n.option.SetName4, internal.Inet4)
		if err != nil {
			return fmt.Errorf("init nftset4 fail: %s", err)
		}
		n.nftset4 = nftset4
	}
	if n.option.TableName6 != "" && n.option.SetName6 != "" {
		nftset6, err := internal.New(n.option.TableName6, n.option.SetName6, internal.Inet6)
		if err != nil {
			return fmt.Errorf("init nftset6 fail: %s", err)
		}
		n.nftset6 = nftset6
	}
	return nil
}

func (n *NftSet) Close() error {
	if n.nftset4 != nil {
		err := n.nftset4.Close()
		if err != nil {
			return fmt.Errorf("close nftset4 conn fail: %s", err)
		}
	}
	if n.nftset6 != nil {
		err := n.nftset6.Close()
		if err != nil {
			return fmt.Errorf("close nftset6 conn fail: %s", err)
		}
	}
	return nil
}

func (n *NftSet) WithContext(_ context.Context) {
}

func (n *NftSet) WithLogger(logger log.ContextLogger) {
	n.logger = logger
}

func (n *NftSet) WithCore(_ adapter.ExecPluginCore) {
}

func (n *NftSet) APIHandler() http.Handler {
	c := chi.NewRouter()
	c.Get("/flush/all", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		go n.flushAll(true, true)
	})
	c.Get("/flush/4", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		go n.flushAll(true, false)
	})
	c.Get("/flush/6", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		go n.flushAll(false, true)
	})
	return c
}

func (n *NftSet) flushAll(inet4, inet6 bool) {
	if n.nftset4 == nil && n.nftset6 == nil {
		return
	}
	if !n.flushLock.TryLock() {
		return
	}
	defer n.flushLock.Unlock()
	if inet4 && n.nftset4 != nil {
		if n.nftset4 != nil {
			n.logger.Info("flush all nftset4")
			err := n.nftset4.FlushAll()
			if err != nil {
				n.logger.Error("flush all nftset4 fail: %s", err)
			}
		}
	}
	if inet6 && n.nftset6 != nil {
		n.logger.Info("flush all nftset6")
		err := n.nftset6.FlushAll()
		if err != nil {
			n.logger.Error("flush all nftset6 fail: %s", err)
		}
	}
}

type dnsAddrRR struct {
	addr netip.Addr
	ttl  time.Duration // second
}

func (n *NftSet) Exec(ctx context.Context, _ map[string]any, dnsCtx *adapter.DNSContext) bool {
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
				n.logger.ErrorContext(ctx, fmt.Sprintf("parse ip %s fail: %s", r.A.String(), err))
				continue
			}
			ip4 = append(ip4, dnsAddrRR{
				addr: ip,
				ttl:  time.Duration(rr.Header().Ttl) * time.Second,
			})
		case *dns.AAAA:
			ip, err := netip.ParseAddr(r.AAAA.String())
			if err != nil {
				n.logger.ErrorContext(ctx, fmt.Sprintf("parse ip %s fail: %s", r.AAAA.String(), err))
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
	if n.nftset4 != nil && len(ip4) > 0 {
		for _, rr := range ip4 {
			ttl := rr.ttl
			if n.option.TTL4 > 0 {
				ttl = time.Duration(n.option.TTL4)
			}
			if n.option.Mask4 > 0 {
				cidr := netip.PrefixFrom(rr.addr, int(n.option.Mask4)).Masked()
				err := n.nftset4.AddCIDR(cidr, ttl)
				if err != nil {
					n.logger.ErrorContext(ctx, fmt.Sprintf("add cidr %s to %s fail: %s", cidr.String(), n.nftset4.Name(), err))
				} else {
					n.logger.DebugContext(ctx, fmt.Sprintf("add cidr %s to %s, ttl: %s", cidr.String(), n.nftset4.Name(), ttl.String()))
				}
			} else {
				err := n.nftset4.AddIP(rr.addr, ttl)
				if err != nil {
					n.logger.ErrorContext(ctx, fmt.Sprintf("add ip %s to %s fail: %s", rr.addr.String(), n.nftset4.Name(), err))
				} else {
					n.logger.DebugContext(ctx, fmt.Sprintf("add ip %s to %s, ttl: %s", rr.addr.String(), n.nftset4.Name(), ttl.String()))
				}
			}
		}
	}
	if n.nftset6 != nil && len(ip6) > 0 {
		for _, rr := range ip6 {
			ttl := rr.ttl
			if n.option.TTL6 > 0 {
				ttl = time.Duration(n.option.TTL6)
			}
			if n.option.Mask6 > 0 {
				cidr := netip.PrefixFrom(rr.addr, int(n.option.Mask6)).Masked()
				err := n.nftset6.AddCIDR(cidr, ttl)
				if err != nil {
					n.logger.ErrorContext(ctx, fmt.Sprintf("add cidr %s to %s fail: %s", cidr.String(), n.nftset6.Name(), err))
				} else {
					n.logger.DebugContext(ctx, fmt.Sprintf("add cidr %s to %s, ttl: %s", cidr.String(), n.nftset6.Name(), ttl.String()))
				}
			} else {
				err := n.nftset6.AddIP(rr.addr, ttl)
				if err != nil {
					n.logger.ErrorContext(ctx, fmt.Sprintf("add ip %s to %s fail: %s", rr.addr.String(), n.nftset6.Name(), err))
				} else {
					n.logger.DebugContext(ctx, fmt.Sprintf("add ip %s to %s, ttl: %s", rr.addr.String(), n.nftset6.Name(), ttl.String()))
				}
			}
		}
	}
	return true
}
