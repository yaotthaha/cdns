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
	"sync/atomic"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option"

	"github.com/fatih/color"
	"github.com/go-chi/chi"
	"github.com/miekg/dns"
)

type MountAPIMatchPlugin interface {
	adapter.MatchPlugin
	adapter.APIHandler
}

type MountAPIExecPlugin interface {
	adapter.ExecPlugin
	adapter.APIHandler
}

type MountStatisticAPIMatchPlugin interface {
	adapter.MatchPlugin
	adapter.StatisticAPIHandler
}

type MountStatisticAPIExecPlugin interface {
	adapter.ExecPlugin
	adapter.StatisticAPIHandler
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
	apiMatchPlugin types.SyncMap[adapter.MatchPlugin, http.Handler]
	apiExecPlugin  types.SyncMap[adapter.ExecPlugin, http.Handler]

	enableStatistic         bool
	statisticAPIUpstream    types.SyncMap[adapter.Upstream, *upstreamStatisticData]
	statisticAPIMatchPlugin types.SyncMap[adapter.MatchPlugin, http.Handler]
	statisticAPIExecPlugin  types.SyncMap[adapter.ExecPlugin, http.Handler]
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
			if a.apiMatchPlugin.Len() > 0 {
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
					handler, ok := a.apiMatchPlugin.Load(matchPlugin)
					if !ok {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					handler.ServeHTTP(w, r)
				}))
			}
			if a.apiExecPlugin.Len() > 0 {
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
					handler, ok := a.apiExecPlugin.Load(execPlugin)
					if !ok {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					handler.ServeHTTP(w, r)
				}))
			}
			if a.enableStatistic {
				r.Mount("/statistic", a.statisticHandler())
				a.logger.Info(fmt.Sprintf("statistic api enabled"))
			}
		})
		go func() {
			err := a.httpServer.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				a.fatalClose(fmt.Errorf("failed to start api server: %s", err))
				a.logger.Error(fmt.Sprintf("failed to start api server: %s", err))
			}
		}()
		a.logger.Info(fmt.Sprintf("api server started at %s", a.httpServer.Addr))
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

func (a *APIServer) MountAPIMatchPlugin(plugin MountAPIMatchPlugin) {
	if plugin == nil || a.chiMux == nil {
		return
	}
	apiHandler := plugin.APIHandler()
	if apiHandler != nil {
		a.apiMatchPlugin.Store(plugin, apiHandler)
	}
}

func (a *APIServer) MountAPIExecPlugin(plugin MountAPIExecPlugin) {
	if plugin == nil || a.chiMux == nil {
		return
	}
	apiHandler := plugin.APIHandler()
	if apiHandler != nil {
		a.apiExecPlugin.Store(plugin, apiHandler)
	}
}

func (a *APIServer) MountMatchStatisticPlugin(plugin MountStatisticAPIMatchPlugin) {
	if plugin == nil || a.chiMux == nil || !a.enableStatistic {
		return
	}
	a.statisticAPIMatchPlugin.Store(plugin, plugin.StatisticAPIHandler())
}

func (a *APIServer) MountExecStatisticPlugin(plugin MountStatisticAPIExecPlugin) {
	if plugin == nil || a.chiMux == nil || !a.enableStatistic {
		return
	}
	a.statisticAPIExecPlugin.Store(plugin, plugin.StatisticAPIHandler())
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
		w.Header().Set("Content-Type", "application/json")
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(rawData)
	})
	if a.statisticAPIMatchPlugin.Len() > 0 {
		chiRouter.Get("/plugin/match", func(w http.ResponseWriter, r *http.Request) {
			matchPlugins := make([]map[string]any, 0)
			a.statisticAPIMatchPlugin.Range(func(plugin adapter.MatchPlugin, _ http.Handler) bool {
				matchPlugins = append(matchPlugins, map[string]any{
					"tag":  plugin.Tag(),
					"type": plugin.Type(),
				})
				return true
			})
			data := map[string]any{
				"plugins": matchPlugins,
			}
			rawData, err := json.Marshal(data)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
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
			handler, ok := a.statisticAPIMatchPlugin.Load(matchPlugin)
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			handler.ServeHTTP(w, r)
		}))
	}
	if a.statisticAPIExecPlugin.Len() > 0 {
		chiRouter.Get("/plugin/exec", func(w http.ResponseWriter, r *http.Request) {
			execPlugins := make([]map[string]any, 0)
			a.statisticAPIExecPlugin.Range(func(plugin adapter.ExecPlugin, _ http.Handler) bool {
				execPlugins = append(execPlugins, map[string]any{
					"tag":  plugin.Tag(),
					"type": plugin.Type(),
				})
				return true
			})
			data := map[string]any{
				"plugins": execPlugins,
			}
			rawData, err := json.Marshal(data)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
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
			handler, ok := a.statisticAPIExecPlugin.Load(execPlugin)
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			handler.ServeHTTP(w, r)
		}))
	}
	return chiRouter
}

func (a *APIServer) upstreamStatisticHook(_ context.Context, upstream adapter.Upstream, _ *dns.Msg, _ *dns.Msg, dnsErr error, _ *adapter.DNSContext) {
	da, _ := a.statisticAPIUpstream.LoadOrStore(upstream, &upstreamStatisticData{})
	da.Total.Add(1)
	if dnsErr != nil {
		da.Fail.Add(1)
	}
}

func (a *APIServer) getUpstreamStatisticData() map[string]any {
	data := make(map[string]any)
	a.statisticAPIUpstream.Range(func(upstream adapter.Upstream, upstreamData *upstreamStatisticData) bool {
		data[upstream.Tag()] = map[string]any{
			"tag":   upstream.Tag(),
			"type":  upstream.Type(),
			"total": upstreamData.Total.Load(),
			"fail":  upstreamData.Fail.Load(),
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
	da, ok := a.statisticAPIUpstream.Load(upstream)
	if !ok {
		return nil
	}
	data := map[string]any{
		"tag":   upstream.Tag(),
		"type":  upstream.Type(),
		"total": da.Total.Load(),
		"fail":  da.Fail.Load(),
	}
	return data
}

type upstreamStatisticData struct {
	Total atomic.Uint64
	Fail  atomic.Uint64
}
