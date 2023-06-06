package core

import (
	"context"
	"fmt"
	"github.com/go-chi/chi"
	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"runtime/debug"
	"strings"
)

type APIServer struct {
	ctx               context.Context
	logger            log.Logger
	debug             bool
	secret            string
	listen            netip.AddrPort
	router            *chi.Mux
	matchPluginRouter *chi.Mux
	execPluginRouter  *chi.Mux
	httpServer        *http.Server
}

func NewAPIServer(ctx context.Context, logger log.Logger, options option.APIOption) (*APIServer, error) {
	a := &APIServer{
		ctx:    ctx,
		logger: log.NewTagLogger(logger, fmt.Sprintf("API Server")),
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
	a.router = chi.NewRouter()
	a.httpServer = &http.Server{
		Addr:    listenAddr.String(),
		Handler: a.router,
	}
	return a, nil
}

func (a *APIServer) Start() error {
	if a.httpServer != nil {
		task := 0
		if a.debug {
			initGoDebugHTTPHandler(a.router)
			task++
		}
		if a.matchPluginRouter != nil {
			a.router.Mount("/plugin/match", a.matchPluginRouter)
			task++
		}
		if a.execPluginRouter != nil {
			a.router.Mount("/plugin/exec", a.execPluginRouter)
			task++
		}
		if task > 0 {
			go func() {
				err := a.httpServer.ListenAndServe()
				if err != nil && err != http.ErrServerClosed {
					a.logger.Error(fmt.Sprintf("failed to start API server: %s", err))
				}
			}()
			a.logger.Info(fmt.Sprintf("API server started at %s", a.httpServer.Addr))
		} else {
			a.matchPluginRouter = nil
			a.execPluginRouter = nil
			a.router = nil
			a.httpServer = nil
		}
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

func (a *APIServer) MountMatchPlugin(plugin adapter.MatchPlugin) {
	apiHandler := plugin.APIHandler()
	if apiHandler == nil {
		return
	}
	if a.matchPluginRouter == nil {
		a.matchPluginRouter = chi.NewRouter()
	}
	a.matchPluginRouter.Mount(fmt.Sprintf("/%s", plugin.Tag()), apiHandler)
}

func (a *APIServer) MountExecPlugin(plugin adapter.ExecPlugin) {
	apiHandler := plugin.APIHandler()
	if apiHandler == nil {
		return
	}
	if a.execPluginRouter == nil {
		a.execPluginRouter = chi.NewRouter()
	}
	a.execPluginRouter.Mount(fmt.Sprintf("/%s", plugin.Tag()), apiHandler)
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
