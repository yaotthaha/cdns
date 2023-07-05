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

var (
	_ adapter.ExecPlugin         = (*Statistic)(nil)
	_ adapter.Starter            = (*Statistic)(nil)
	_ adapter.WithContext        = (*Statistic)(nil)
	_ adapter.WithContextLogger  = (*Statistic)(nil)
	_ adapter.WithExecPluginCore = (*Statistic)(nil)
	_ adapter.APIHandler         = (*Statistic)(nil)
)

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
	}
	return nil
}

func (s *Statistic) WithContext(ctx context.Context) {
	s.ctx = ctx
}

func (s *Statistic) WithContextLogger(contextLogger log.ContextLogger) {
	s.logger = contextLogger
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(info)
	})
	c.Mount("/ws", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respHeader := http.Header{}
		respHeader.Set("Content-Type", "application/json")
		wsConn, err := upgrader.Upgrade(w, r, respHeader)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		isClosed := atomic.Bool{}
		defer func() {
			isClosed.Store(true)
			wsConn.Close()
		}()
		sleepTime := 1 * time.Second
		if sleepSecond := r.URL.Query().Get("seconds"); sleepSecond != "" {
			sleepSecondUint, err := strconv.ParseUint(sleepSecond, 10, 64)
			if err == nil {
				sleepTime = time.Duration(sleepSecondUint) * time.Second
			}
		}
		go func() {
			for {
				select {
				case <-s.ctx.Done():
					return
				default:
				}
				if isClosed.Load() {
					return
				}
				msType, _, err := wsConn.ReadMessage()
				if err != nil {
					continue
				}
				if msType == websocket.CloseMessage {
					isClosed.Store(true)
					wsConn.Close()
					return
				}
			}
		}()
		ticker := time.NewTicker(sleepTime)
		defer ticker.Stop()
		for {
			if isClosed.Load() {
				return
			}
			select {
			case <-ticker.C:
				wsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				err := wsConn.WriteJSON(s.getInfo())
				if err != nil {
					continue
				}
			case <-s.ctx.Done():
				return
			}
		}
	}))
	c.Get("/clean", func(w http.ResponseWriter, r *http.Request) {
		go s.clean()
		w.WriteHeader(http.StatusNoContent)
	})
	return c
}

type info struct {
	Total    uint64         `json:"total"`
	Upstream []upstreamInfo `json:"upstreams,omitempty"`
}

type upstreamInfo struct {
	Tag     string `json:"tag"`
	Type    string `json:"type"`
	Total   uint64 `json:"total"`
	Fail    uint64 `json:"fail"`
	AvgTime uint64 `json:"avg_time"`
}

func (s *Statistic) getInfo() info {
	total := s.totalQueryCount.Load()
	upstreamInfos := make([]upstreamInfo, 0)
	for _, upstream := range s.upstreamMap {
		var (
			total   uint64
			fail    uint64
			avgTime uint64
		)
		tqc := s.upstreamTotalQueryCount.Get(upstream)
		if tqc != nil {
			total = tqc.Load()
		}
		fqc := s.upstreamFailQueryCount.Get(upstream)
		if fqc != nil {
			fail = fqc.Load()
		}
		at := s.upstreamAvgTime.Get(upstream)
		if at != nil {
			avgTime = uint64(at.Load())
		}
		if total == 0 && fail == 0 && avgTime == 0 {
			continue
		}
		info := upstreamInfo{
			Tag:     upstream.Tag(),
			Type:    upstream.Type(),
			Total:   total,
			Fail:    fail,
			AvgTime: avgTime,
		}
		upstreamInfos = append(upstreamInfos, info)
	}
	return info{
		Total:    total,
		Upstream: upstreamInfos,
	}
}

func (s *Statistic) clean() {
	s.totalQueryCount.Store(0)
	for _, upstream := range s.upstreamMap {
		s.upstreamTotalQueryCount.Get(upstream).Store(0)
		s.upstreamFailQueryCount.Get(upstream).Store(0)
		s.upstreamAvgTime.Get(upstream).Reset()
	}
}

func (s *Statistic) Exec(_ context.Context, _ map[string]any, dnsCtx *adapter.DNSContext) bool {
	s.totalQueryCount.Add(1)
	dnsCtx.RangeKV(func(key string, value any) bool {
		upstreamTag, ok := strings.CutPrefix(key, "upstream-time-consuming-")
		if ok && upstreamTag != "" {
			if tc, ok := value.(time.Duration); ok {
				upstream := s.upstreamMap[upstreamTag]
				tqc := s.upstreamTotalQueryCount.Get(upstream)
				if tqc == nil {
					tqc = new(atomic.Uint64)
					s.upstreamTotalQueryCount.Set(upstream, tqc)
				}
				tqc.Add(1)
				if tc == -1 {
					fqc := s.upstreamFailQueryCount.Get(upstream)
					if fqc == nil {
						fqc = new(atomic.Uint64)
						s.upstreamFailQueryCount.Set(upstream, fqc)
					}
					fqc.Add(1)
				} else {
					at := s.upstreamAvgTime.Get(upstream)
					if at == nil {
						at = avg.NewAvg[int64]()
						s.upstreamAvgTime.Set(upstream, at)
					}
					at.Avg(tc.Milliseconds())
				}
			}
		}
		return true
	})
	return true
}
