package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option"

	"github.com/fatih/color"
	"github.com/go-chi/chi"
	"github.com/miekg/dns"
)

type MountMatchPlugin interface {
	adapter.MatchPlugin
	adapter.APIHandler
}

type MountExecPlugin interface {
	adapter.ExecPlugin
	adapter.APIHandler
}

type APIServer struct {
	ctx            context.Context
	core           adapter.Core
	fatalClose     func(error)
	logger         log.ContextLogger
	debug          bool
	secret         string
	listen         netip.AddrPort
	chiMux         *chi.Mux
	httpServer     *http.Server
	matchPluginAPI types.SyncMap[adapter.MatchPlugin, http.Handler]
	execPluginAPI  types.SyncMap[adapter.ExecPlugin, http.Handler]
	execLock       sync.Mutex

	enableStatistic         bool
	upstreamStatisticMap    types.SyncMap[adapter.Upstream, *upstreamStatisticData]
	matchPluginStatisticMap types.SyncMap[adapter.MatchPlugin, adapter.WithMatchPluginStatisticAPIHandler]
	execPluginStatisticMap  types.SyncMap[adapter.ExecPlugin, adapter.WithExecPluginStatisticAPIHandler]
}

func NewAPIServer(ctx context.Context, core adapter.Core, logger log.Logger, options option.APIOptions) (*APIServer, error) {
	a := &APIServer{
		ctx:    ctx,
		core:   core,
		logger: log.NewContextLogger(log.NewTagLogger(logger, fmt.Sprintf("api server"))),
	}
	if clogger, isSetColorLogger := a.logger.(log.SetColorLogger); isSetColorLogger {
		clogger.SetColor(color.FgYellow)
	}
	if options.Listen == "" {
		return a, nil
	}
	listenAddr, err := netip.ParseAddrPort(options.Listen)
	if err != nil {
		return nil, fmt.Errorf("invalid listen address: %s", err)
	}
	a.secret = options.Secret
	a.debug = options.Debug
	a.enableStatistic = options.EnableStatistic
	a.chiMux = chi.NewMux()
	a.chiMux.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	a.httpServer = &http.Server{
		Addr:    listenAddr.String(),
		Handler: a.chiMux,
	}
	return a, nil
}

func (a *APIServer) WithFatalCloser(f func(error)) {
	a.fatalClose = f
}

func (a *APIServer) Start() error {
	if a.httpServer != nil {
		a.chiMux.Route("/", func(r chi.Router) {
			if a.debug {
				initGoDebugHTTPHandler(a.chiMux)
			}
			r.Use(a.prepare)
			r.Use(a.recover)
			r.Use(a.debugLog)
			if a.secret != "" {
				r.Use(a.auth)
			}
			if a.matchPluginAPI.Len() > 0 {
				r.Mount("/plugin/match/{matchPluginTag}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					matchPluginTag := chi.URLParam(r, "matchPluginTag")
					if matchPluginTag == "" {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					matchPlugin := a.core.GetMatchPlugin(matchPluginTag)
					if matchPlugin == nil {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					handler, ok := a.matchPluginAPI.Load(matchPlugin)
					if !ok {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					handler.ServeHTTP(w, r)
				}))
			}
			if a.execPluginAPI.Len() > 0 {
				r.Mount("/plugin/exec/{execPluginTag}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					execPluginTag := chi.URLParam(r, "execPluginTag")
					if execPluginTag == "" {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					execPlugin := a.core.GetExecPlugin(execPluginTag)
					if execPlugin == nil {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					handler, ok := a.execPluginAPI.Load(execPlugin)
					if !ok {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					handler.ServeHTTP(w, r)
				}))
			}
			if a.enableStatistic {
				r.Mount("/statistic", a.statisticHandler())
			}
		})
		go func() {
			err := a.httpServer.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				a.fatalClose(fmt.Errorf("failed to start API server: %s", err))
				a.logger.Error(fmt.Sprintf("failed to start API server: %s", err))
			}
		}()
		a.logger.Info(fmt.Sprintf("API server started at %s", a.httpServer.Addr))
	}
	return nil
}

func (a *APIServer) Close() error {
	if a.httpServer != nil {
		err := a.httpServer.Close()
		if err != nil {
			return err
		}
		a.logger.Info("api server close")
	}
	return nil
}

func (a *APIServer) MountMatchPlugin(plugin MountMatchPlugin) {
	if plugin == nil || a.chiMux == nil {
		return
	}
	apiHandler := plugin.APIHandler()
	if apiHandler != nil {
		a.matchPluginAPI.Store(plugin, apiHandler)
	}
}

func (a *APIServer) MountExecPlugin(plugin MountExecPlugin) {
	if plugin == nil || a.chiMux == nil {
		return
	}
	apiHandler := plugin.APIHandler()
	if apiHandler != nil {
		a.execPluginAPI.Store(plugin, apiHandler)
	}
}

func (a *APIServer) MountMatchStatisticPlugin(plugin adapter.WithMatchPluginStatisticAPIHandler) {
	if plugin == nil || a.chiMux == nil || !a.enableStatistic {
		return
	}
	a.matchPluginStatisticMap.Store(plugin, plugin)
}

func (a *APIServer) MountExecStatisticPlugin(plugin adapter.WithExecPluginStatisticAPIHandler) {
	if plugin == nil || a.chiMux == nil || !a.enableStatistic {
		return
	}
	a.execPluginStatisticMap.Store(plugin, plugin)
}

func (a *APIServer) prepare(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(log.AddContextTag(r.Context())))
	}
	return http.HandlerFunc(fn)
}

func (a *APIServer) auth(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if a.secret != "" {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			bearer, token, ok := strings.Cut(authHeader, " ")
			if !ok || bearer != "Bearer" || token != a.secret {
				a.logger.WarnContext(r.Context(), fmt.Sprintf("unauthorized request"))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		}
	}
	return http.HandlerFunc(fn)
}

func (a *APIServer) recover(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				ctx := r.Context()
				a.logger.PrintContext(ctx, "Panic", fmt.Sprintf("panic: %s", err))
				var stackBuf []byte
				n := runtime.Stack(stackBuf, false)
				a.logger.PrintContext(ctx, "Panic", fmt.Sprintf("stack: %s", stackBuf[:n]))
			}
		}()
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func (a *APIServer) debugLog(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		a.logger.DebugContext(r.Context(), fmt.Sprintf("method: %s | client: %s | path: %s", r.Method, r.RemoteAddr, r.URL.Path))
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func initGoDebugHTTPHandler(r *chi.Mux) {
	r.Route("/debug", func(r chi.Router) {
		r.Get("/gc", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
			go debug.FreeOSMemory()
		})
		r.HandleFunc("/pprof", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/debug/pprof/", http.StatusMovedPermanently)
		})
		r.HandleFunc("/pprof/*", pprof.Index)
		r.HandleFunc("/pprof/cmdline", pprof.Cmdline)
		r.HandleFunc("/pprof/profile", pprof.Profile)
		r.HandleFunc("/pprof/symbol", pprof.Symbol)
		r.HandleFunc("/pprof/trace", pprof.Trace)
	})
}

func (a *APIServer) statisticHandler() http.Handler {
	chiRouter := chi.NewRouter()
	chiRouter.Get("/upstream", func(w http.ResponseWriter, r *http.Request) {
		data := a.getUpstreamStatisticData()
		rawData, err := json.Marshal(data)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(rawData)
	})
	chiRouter.Get("/upstream/{upstreamTag}", func(w http.ResponseWriter, r *http.Request) {
		upstreamTag := chi.URLParam(r, "upstreamTag")
		if upstreamTag == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		data := a.getUpstreamStatisticDataFromTag(upstreamTag)
		if data == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		rawData, err := json.Marshal(data)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(rawData)
	})
	if a.matchPluginStatisticMap.Len() > 0 {
		chiRouter.Get("/plugin/match", func(w http.ResponseWriter, r *http.Request) {
			matchPluginTags := make([]string, 0)
			a.matchPluginStatisticMap.Range(func(_ adapter.MatchPlugin, value adapter.WithMatchPluginStatisticAPIHandler) bool {
				matchPluginTags = append(matchPluginTags, value.Tag())
				return true
			})
			data := map[string]any{
				"plugins": matchPluginTags,
			}
			rawData, err := json.Marshal(data)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write(rawData)
		})
		chiRouter.Mount("/plugin/match/{matchPluginTag}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			matchPluginTag := chi.URLParam(r, "matchPluginTag")
			if matchPluginTag == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			matchPlugin := a.core.GetMatchPlugin(matchPluginTag)
			if matchPlugin == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			handler, ok := a.matchPluginStatisticMap.Load(matchPlugin)
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			handler.StatisticAPIHandler().ServeHTTP(w, r)
		}))
	}
	if a.execPluginStatisticMap.Len() > 0 {
		chiRouter.Get("/plugin/exec", func(w http.ResponseWriter, r *http.Request) {
			execPluginTags := make([]string, 0)
			a.execPluginStatisticMap.Range(func(_ adapter.ExecPlugin, value adapter.WithExecPluginStatisticAPIHandler) bool {
				execPluginTags = append(execPluginTags, value.Tag())
				return true
			})
			data := map[string]any{
				"plugins": execPluginTags,
			}
			rawData, err := json.Marshal(data)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write(rawData)
		})
		chiRouter.Mount("/plugin/exec/{execPluginTag}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			execPluginTag := chi.URLParam(r, "execPluginTag")
			if execPluginTag == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			execPlugin := a.core.GetExecPlugin(execPluginTag)
			if execPlugin == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			handler, ok := a.execPluginStatisticMap.Load(execPlugin)
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			handler.StatisticAPIHandler().ServeHTTP(w, r)
		}))
	}
	return chiRouter
}

func (a *APIServer) upstreamStatisticHook(_ context.Context, upstream adapter.Upstream, _ *dns.Msg, _ *dns.Msg, dnsErr error, _ *adapter.DNSContext) {
	da, _ := a.upstreamStatisticMap.LoadOrStore(upstream, &upstreamStatisticData{})
	da.Total.Add(1)
	if dnsErr != nil {
		da.Fail.Add(1)
	}
}

func (a *APIServer) getUpstreamStatisticData() map[string]any {
	data := make(map[string]any)
	a.upstreamStatisticMap.Range(func(key adapter.Upstream, value *upstreamStatisticData) bool {
		data[key.Tag()] = map[string]any{
			"total": value.Total.Load(),
			"fail":  value.Fail.Load(),
		}
		return true
	})
	return data
}

func (a *APIServer) getUpstreamStatisticDataFromTag(upstreamTag string) map[string]any {
	upstream := a.core.GetUpstream(upstreamTag)
	if upstream == nil {
		return nil
	}
	da, ok := a.upstreamStatisticMap.Load(upstream)
	if !ok {
		return nil
	}
	data := map[string]any{
		"total": da.Total.Load(),
		"fail":  da.Fail.Load(),
	}
	return data
}

type upstreamStatisticData struct {
	Total atomic.Uint64
	Fail  atomic.Uint64
}
