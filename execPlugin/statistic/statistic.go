package statistic

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/execPlugin/statistic/avg"
	"github.com/yaotthaha/cdns/execPlugin/statistic/safemap"
	"github.com/yaotthaha/cdns/log"

	"github.com/go-chi/chi"
	"github.com/gorilla/websocket"
)

var _ adapter.ExecPlugin = (*Statistic)(nil)

const PluginType = "statistic"

func init() {
	adapter.RegisterExecPlugin(PluginType, NewStatistic)
}

type Statistic struct {
	tag    string
	ctx    context.Context
	logger log.ContextLogger
	core   adapter.ExecPluginCore

	totalQueryCount         atomic.Uint64
	upstreamMap             map[string]adapter.Upstream
	upstreamTotalQueryCount *safemap.SafeMap[adapter.Upstream, *atomic.Uint64]
	upstreamFailQueryCount  *safemap.SafeMap[adapter.Upstream, *atomic.Uint64]
	upstreamAvgTime         *safemap.SafeMap[adapter.Upstream, *avg.Avg[int64]]
}

func NewStatistic(tag string, _ map[string]any) (adapter.ExecPlugin, error) {
	return &Statistic{
		tag: tag,
	}, nil
}

func (s *Statistic) Tag() string {
	return s.tag
}

func (s *Statistic) Type() string {
	return PluginType
}

func (s *Statistic) Start() error {
	upstreams := s.core.ListUpstream()
	s.upstreamMap = make(map[string]adapter.Upstream)
	s.upstreamTotalQueryCount = safemap.NewSafeMap[adapter.Upstream, *atomic.Uint64]()
	s.upstreamFailQueryCount = safemap.NewSafeMap[adapter.Upstream, *atomic.Uint64]()
	s.upstreamAvgTime = safemap.NewSafeMap[adapter.Upstream, *avg.Avg[int64]]()
	for _, upstream := range upstreams {
		s.upstreamMap[upstream.Tag()] = upstream
		s.upstreamTotalQueryCount.Set(upstream, new(atomic.Uint64))
		s.upstreamFailQueryCount.Set(upstream, new(atomic.Uint64))
		s.upstreamAvgTime.Set(upstream, avg.NewAvg[int64]())
	}
	return nil
}

func (s *Statistic) Close() error {
	return nil
}

func (s *Statistic) WithContext(ctx context.Context) {
	s.ctx = ctx
}

func (s *Statistic) WithLogger(logger log.ContextLogger) {
	s.logger = logger
}

func (s *Statistic) WithCore(core adapter.ExecPluginCore) {
	s.core = core
}

var upgrader = websocket.Upgrader{}

func (s *Statistic) APIHandler() http.Handler {
	c := chi.NewRouter()
	c.Get("/info", func(w http.ResponseWriter, r *http.Request) {
		info, err := json.Marshal(s.getInfo())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(info)
	})
	c.Mount("/ws", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer wsConn.Close()
		sleepTime := 1 * time.Second
		if sleepSecond := r.URL.Query().Get("seconds"); sleepSecond != "" {
			sleepSecondUint, err := strconv.ParseUint(sleepSecond, 10, 64)
			if err == nil {
				sleepTime = time.Duration(sleepSecondUint) * time.Second
			}
		}
		ticker := time.NewTicker(sleepTime)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				wsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				err := wsConn.WriteJSON(s.getInfo())
				if err != nil {
					return
				}
			case <-s.ctx.Done():
				return
			}
		}
	}))
	return c
}

type info struct {
	Total    uint64         `json:"total"`
	Upstream []upstreamInfo `json:"upstreams,omitempty"`
}

type upstreamInfo struct {
	Tag     string `json:"tag"`
	Total   uint64 `json:"total"`
	Fail    uint64 `json:"fail"`
	AvgTime uint64 `json:"avg_time"`
}

func (s *Statistic) getInfo() info {
	total := s.totalQueryCount.Load()
	upstreamInfos := make([]upstreamInfo, 0)
	for _, upstream := range s.upstreamMap {
		info := upstreamInfo{
			Tag:     upstream.Tag(),
			Total:   s.upstreamTotalQueryCount.Get(upstream).Load(),
			Fail:    s.upstreamFailQueryCount.Get(upstream).Load(),
			AvgTime: uint64(s.upstreamAvgTime.Get(upstream).Load()),
		}
		upstreamInfos = append(upstreamInfos, info)
	}
	return info{
		Total:    total,
		Upstream: upstreamInfos,
	}
}

func (s *Statistic) Exec(_ context.Context, _ map[string]any, dnsCtx *adapter.DNSContext) bool {
	s.totalQueryCount.Add(1)
	dnsCtx.RangeKV(func(key string, value any) bool {
		upstreamTag, ok := strings.CutPrefix(key, "upstream-time-consuming-")
		if ok && upstreamTag != "" {
			if tc, ok := value.(time.Duration); ok {
				upstream := s.upstreamMap[upstreamTag]
				s.upstreamTotalQueryCount.Get(upstream).Add(1)
				if tc == -1 {
					s.upstreamFailQueryCount.Get(upstream).Add(1)
				} else {
					s.upstreamAvgTime.Get(upstream).Avg(tc.Milliseconds())
				}
			}
		}
		return true
	})
	return true
}
