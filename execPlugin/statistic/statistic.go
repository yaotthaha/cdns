package statistic

import (
	"context"
	"net/http"
	"sync/atomic"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/lib/types"

	"github.com/go-chi/chi"
	"github.com/miekg/dns"
)

const PluginType = "statistic"

func init() {
	adapter.RegisterExecPlugin(PluginType, NewStatistic)
}

var (
	_ adapter.ExecPlugin         = (*Statistic)(nil)
	_ adapter.WithContext        = (*Statistic)(nil)
	_ adapter.WithExecPluginCore = (*Statistic)(nil)
	_ adapter.APIHandler         = (*Statistic)(nil)
)

type data struct {
	total atomic.Uint64
	fail  atomic.Uint64
}

func (d *data) Clone() types.CloneableValue {
	da := &data{}
	da.total.Store(d.total.Load())
	da.fail.Store(d.fail.Load())
	return da
}

func (d *data) Value() any {
	return d
}

type Statistic struct {
	tag  string
	ctx  context.Context
	core adapter.ExecPluginCore

	postUpstreamHookFuncPointer *adapter.PostUpstreamHookFunc
	upstreamMap                 types.CloneableSyncMap[adapter.Upstream, *data]
}

func NewStatistic(tag string, _ map[string]any) (adapter.ExecPlugin, error) {
	s := &Statistic{
		tag: tag,
	}

	postUpstreamHookFunc := s.PostUpstreamHook
	s.postUpstreamHookFuncPointer = (*adapter.PostUpstreamHookFunc)(&postUpstreamHookFunc)
	return s, nil
}

func (s *Statistic) Tag() string {
	return s.tag
}

func (s *Statistic) Type() string {
	return PluginType
}

func (s *Statistic) WithContext(ctx context.Context) {
	s.ctx = ctx
}

func (s *Statistic) WithCore(core adapter.ExecPluginCore) {
	s.core = core
}

func (s *Statistic) Exec(_ context.Context, _ map[string]any, dnsCtx *adapter.DNSContext) bool {
	dnsCtx.PostUpstreamHook.Append(s.postUpstreamHookFuncPointer)
	return true
}

func (s *Statistic) PostUpstreamHook(_ context.Context, upstream adapter.Upstream, _ *dns.Msg, _ *dns.Msg, dnsErr error, _ *adapter.DNSContext) {
	da, _ := s.upstreamMap.LoadOrStore(upstream, &data{})
	da.total.Add(1)
	if dnsErr != nil {
		da.fail.Add(1)
	}
}

func (s *Statistic) APIHandler() http.Handler {
	chiRouter := chi.NewRouter()
	return chiRouter
}

func (s *Statistic) getUpstreamData(upstreamTag string) map[string]any {
	upstream := s.core.GetUpstream(upstreamTag)
	if upstream == nil {
		return nil
	}
	da, ok := s.upstreamMap.Load(upstream)
	if !ok {
		return nil
	}
	return map[string]any{
		"total": da.total.Load(),
		"fail":  da.fail.Load(),
	}
}

func (s *Statistic) getData() map[string]any {
	m := make(map[string]any)
	s.upstreamMap.Range(func(key adapter.Upstream, value *data) bool {
		m[key.Tag()] = map[string]any{
			"total": value.total.Load(),
			"fail":  value.fail.Load(),
		}
		return true
	})
	return m
}
