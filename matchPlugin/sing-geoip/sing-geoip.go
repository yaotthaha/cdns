package sing_geoip

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/matchPlugin/sing-geoip/geoip"

	"github.com/go-chi/chi"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

const PluginType = "sing-geoip"

var _ adapter.MatchPlugin = (*SingGeoIP)(nil)

func init() {
	adapter.RegisterMatchPlugin(PluginType, NewSingGeoIP)
}

type SingGeoIP struct {
	tag        string
	ctx        context.Context
	logger     log.ContextLogger
	reloadLock sync.Mutex
	file       string
	reader     atomic.Pointer[geoip.Reader]
}

type option struct {
	File string `yaml:"file"`
}

func NewSingGeoIP(tag string, args map[string]any) (adapter.MatchPlugin, error) {
	c := &SingGeoIP{
		tag: tag,
	}

	optionBytes, err := yaml.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("parse args fail: %s", err)
	}
	var op option
	err = yaml.Unmarshal(optionBytes, &op)
	if err != nil {
		return nil, fmt.Errorf("parse args fail: %s", err)
	}

	if op.File == "" {
		return nil, fmt.Errorf("file is empty")
	}
	c.file = op.File

	return c, nil
}

func (s *SingGeoIP) Tag() string {
	return s.tag
}

func (s *SingGeoIP) Type() string {
	return PluginType
}

func (s *SingGeoIP) Start() error {
	reader, codes, err := s.loadGeoIP()
	if err != nil {
		return fmt.Errorf("read geoip file fail: %s", err)
	}
	s.logger.Info(fmt.Sprintf("load geoip file success: %d", len(codes)))
	s.reader.Store(reader)
	return nil
}

func (s *SingGeoIP) Close() error {
	return nil
}

func (s *SingGeoIP) WithContext(ctx context.Context) {
	s.ctx = ctx
}

func (s *SingGeoIP) WithLogger(contextLogger log.ContextLogger) {
	s.logger = contextLogger
}

func (s *SingGeoIP) APIHandler() http.Handler {
	r := chi.NewRouter()
	r.Get("/reload", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		go s.reloadGeoIP()
	})
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	return r
}

func (s *SingGeoIP) reloadGeoIP() {
	if !s.reloadLock.TryLock() {
		return
	}
	defer s.reloadLock.Unlock()
	startTime := time.Now()
	s.logger.Info("reload geoip...")
	reader, codes, err := s.loadGeoIP()
	if err != nil {
		s.logger.Error(fmt.Sprintf("reload geoip fail: %s", err))
		return
	}
	s.reader.Store(reader)
	s.logger.Info(fmt.Sprintf("reload geoip success: %d, cost: %s", len(codes), time.Since(startTime).String()))
}

func (s *SingGeoIP) Match(ctx context.Context, args map[string]any, dnsCtx *adapter.DNSContext) bool {
	if dnsCtx.RespMsg == nil || dnsCtx.RespMsg.Answer == nil || len(dnsCtx.RespMsg.Answer) == 0 {
		return false
	}
	ips := make([]net.IP, 0)
	for _, rr := range dnsCtx.RespMsg.Answer {
		switch r := rr.(type) {
		case *dns.A:
			ips = append(ips, r.A)
		case *dns.AAAA:
			ips = append(ips, r.AAAA)
		default:
			continue
		}
	}
	if len(ips) == 0 {
		return false
	}
	codeAnyListAny, ok := args["code"]
	if !ok {
		s.logger.ErrorContext(ctx, fmt.Sprintf("code type error: %T", args["code"]))
		return false
	}
	codeMap := make(map[string]bool)
	codeAnyList, ok := codeAnyListAny.([]any)
	if !ok {
		codeItem, ok := codeAnyListAny.(string)
		if !ok {
			s.logger.ErrorContext(ctx, fmt.Sprintf("code type error: %T", args["code"]))
			return false
		}
		codeMap[codeItem] = true
	} else {
		for _, codeAny := range codeAnyList {
			codeItem, ok := codeAny.(string)
			if !ok {
				s.logger.ErrorContext(ctx, fmt.Sprintf("code type error: %T", args["code"]))
				return false
			}
			codeMap[codeItem] = true
		}
	}
	reader := s.reader.Load()
	if reader != nil {
		for _, ip := range ips {
			select {
			case <-ctx.Done():
				return false
			default:
			}
			code := reader.Lookup(ip)
			if code == "unknown" {
				continue
			}
			if codeMap[code] {
				s.logger.DebugContext(ctx, fmt.Sprintf("match sing-geoip: %s", code))
				return true
			}
		}
	}
	return false
}

func (s *SingGeoIP) loadGeoIP() (*geoip.Reader, []string, error) {
	return geoip.Open(s.file)
}
