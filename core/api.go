package core

import (
	"context"
	"fmt"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option"

	"github.com/fatih/color"
	"github.com/go-chi/chi"
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
	fatalClose     func(error)
	logger         log.Logger
	debug          bool
	secret         string
	listen         netip.AddrPort
	chiMux         *chi.Mux
	httpServer     *http.Server
	matchPluginAPI map[string]http.Handler
	matchLock      sync.Mutex
	execPluginAPI  map[string]http.Handler
	execLock       sync.Mutex
}

func NewAPIServer(ctx context.Context, logger log.Logger, options option.APIOptions) (*APIServer, error) {
	a := &APIServer{
		ctx:    ctx,
		logger: log.NewTagLogger(logger, fmt.Sprintf("api server")),
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
			if a.secret != "" {
				r.Use(a.auth)
			}
			a.matchLock.Lock()
			if a.matchPluginAPI != nil {
				for tag, handler := range a.matchPluginAPI {
					r.Mount("/plugin/match/"+tag, handler)
				}
			}
			a.matchLock.Unlock()
			a.execLock.Lock()
			if a.execPluginAPI != nil {
				for tag, handler := range a.execPluginAPI {
					r.Mount("/plugin/exec/"+tag, handler)
				}
			}
			a.execLock.Unlock()
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
		a.matchLock.Lock()
		defer a.matchLock.Unlock()
		if a.matchPluginAPI == nil {
			a.matchPluginAPI = make(map[string]http.Handler)
		}
		a.matchPluginAPI[plugin.Tag()] = apiHandler
	}
}

func (a *APIServer) MountExecPlugin(plugin MountExecPlugin) {
	if plugin == nil || a.chiMux == nil {
		return
	}
	apiHandler := plugin.APIHandler()
	if apiHandler != nil {
		a.execLock.Lock()
		defer a.execLock.Unlock()
		if a.execPluginAPI == nil {
			a.execPluginAPI = make(map[string]http.Handler)
		}
		a.execPluginAPI[plugin.Tag()] = apiHandler
	}
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
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		}
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
