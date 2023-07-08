package core

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/execPlugin"
	"github.com/yaotthaha/cdns/lib/tools"
	"github.com/yaotthaha/cdns/listener"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/matchPlugin"
	"github.com/yaotthaha/cdns/option"
	"github.com/yaotthaha/cdns/upstream"
	"github.com/yaotthaha/cdns/workflow"

	"github.com/fatih/color"
	"github.com/miekg/dns"
)

type Core struct {
	ctx              context.Context
	startFatalCtx    context.Context
	startFatalCloser context.CancelCauseFunc
	logger           log.Logger
	apiServer        *APIServer
	upstreams        map[string]adapter.Upstream
	upstreamArr      []adapter.Upstream
	workflows        map[string]adapter.Workflow
	matchPlugins     map[string]adapter.MatchPlugin
	execPlugins      map[string]adapter.ExecPlugin
	listeners        map[string]adapter.Listener
}

func init() {
	matchPlugin.Register()
	execPlugin.Register()
}

func New(ctx context.Context, logger log.Logger, options option.Option) (adapter.Core, error) {
	core := &Core{
		ctx:    ctx,
		logger: log.NewTagLogger(logger, "core"),
	}
	if clogger, isSetColorLogger := core.logger.(log.SetColorLogger); isSetColorLogger {
		clogger.SetColor(color.FgYellow)
	}
	// Init API Server
	apiServer, err := NewAPIServer(ctx, core, logger, options.APIOptions)
	if err != nil {
		return nil, fmt.Errorf("init api server fail: %s", err)
	}
	core.apiServer = apiServer
	// Init Upstreams
	if options.UpstreamOptions == nil || len(options.UpstreamOptions) == 0 {
		return nil, fmt.Errorf("no upstreams found")
	}
	core.upstreams = make(map[string]adapter.Upstream)
	core.upstreamArr = make([]adapter.Upstream, 0)
	for _, u := range options.UpstreamOptions {
		if u.Tag == "" {
			return nil, fmt.Errorf("init upstream fail: tag is empty")
		}
		if _, ok := core.upstreams[u.Tag]; ok {
			return nil, fmt.Errorf("init upstream fail: tag %s duplicated", u.Tag)
		}
		tagLogger := log.NewTagLogger(core.logger, fmt.Sprintf("upstream/%s", u.Tag))
		if clogger, isSetColorLogger := tagLogger.(log.SetColorLogger); isSetColorLogger {
			clogger.SetColor(color.FgCyan)
		}
		logger := log.NewContextLogger(tagLogger)
		up, err := upstream.NewUpstream(ctx, logger, u)
		if err != nil {
			return nil, fmt.Errorf("init upstream fail: %s", err)
		}
		if wc, ok := up.(adapter.WithCore); ok {
			wc.WithCore(core)
		}
		core.upstreams[u.Tag] = up
		core.upstreamArr = append(core.upstreamArr, up)
	}
	upstreams, err := sortUpstreams(core.upstreamArr)
	if err != nil {
		return nil, err
	}
	core.upstreamArr = upstreams
	// Init Match Plugins
	if options.MatchPluginOptions != nil && len(options.MatchPluginOptions) > 0 {
		core.matchPlugins = make(map[string]adapter.MatchPlugin)
		for _, m := range options.MatchPluginOptions {
			if m.Tag == "" {
				return nil, fmt.Errorf("init match plugin fail: tag is empty")
			}
			if _, ok := core.matchPlugins[m.Tag]; ok {
				return nil, fmt.Errorf("init match plugin fail: tag %s duplicated", m.Tag)
			}
			mp, err := adapter.NewMatchPlugin(m.Type, m.Tag, m.Args)
			if err != nil {
				return nil, fmt.Errorf("init match plugin %s fail: %s", m.Tag, err)
			}
			if wc, ok := mp.(adapter.WithContext); ok {
				wc.WithContext(ctx)
			}
			if wl, ok := mp.(adapter.WithContextLogger); ok {
				tagLogger := log.NewTagLogger(logger, fmt.Sprintf("match-plugin/%s", mp.Tag()))
				if clogger, isSetColorLogger := tagLogger.(log.SetColorLogger); isSetColorLogger {
					clogger.SetColor(color.FgBlue)
				}
				wl.WithContextLogger(log.NewContextLogger(tagLogger))
			}
			if wc, ok := mp.(adapter.WithMatchPluginCore); ok {
				wc.WithCore(core)
			}
			if mp, ok := mp.(MountMatchPlugin); ok {
				core.apiServer.MountMatchPlugin(mp)
			}
			core.matchPlugins[m.Tag] = mp
		}
	}
	// Init Exec Plugins
	if options.ExecPluginOptions != nil && len(options.ExecPluginOptions) > 0 {
		core.execPlugins = make(map[string]adapter.ExecPlugin)
		for _, e := range options.ExecPluginOptions {
			if e.Tag == "" {
				return nil, fmt.Errorf("init exec plugin fail: tag is empty")
			}
			if _, ok := core.execPlugins[e.Tag]; ok {
				return nil, fmt.Errorf("init exec plugin fail: tag %s duplicated", e.Tag)
			}
			ep, err := adapter.NewExecPlugin(e.Type, e.Tag, e.Args)
			if err != nil {
				return nil, fmt.Errorf("init exec plugin %s init fail: %s", e.Tag, err)
			}
			if wc, ok := ep.(adapter.WithContext); ok {
				wc.WithContext(ctx)
			}
			if wl, ok := ep.(adapter.WithContextLogger); ok {
				tagLogger := log.NewTagLogger(logger, fmt.Sprintf("exec-plugin/%s", ep.Tag()))
				if clogger, isSetColorLogger := tagLogger.(log.SetColorLogger); isSetColorLogger {
					clogger.SetColor(color.FgBlue)
				}
				wl.WithContextLogger(log.NewContextLogger(tagLogger))
			}
			if wc, ok := ep.(adapter.WithExecPluginCore); ok {
				wc.WithCore(core)
			}
			if mp, ok := ep.(MountExecPlugin); ok {
				core.apiServer.MountExecPlugin(mp)
			}
			core.execPlugins[e.Tag] = ep
		}
	}
	// Init Workflows
	if options.WorkflowOptions == nil || len(options.WorkflowOptions) == 0 {
		return nil, fmt.Errorf("init workflow: no workflows found")
	}
	core.workflows = make(map[string]adapter.Workflow)
	for _, w := range options.WorkflowOptions {
		if w.Tag == "" {
			return nil, fmt.Errorf("init workflow fail: tag is empty")
		}
		if _, ok := core.workflows[w.Tag]; ok {
			return nil, fmt.Errorf("init workflow fail: tag %s duplicated", w.Tag)
		}
		tagLogger := log.NewTagLogger(logger, fmt.Sprintf("workflow/%s", w.Tag))
		if clogger, isSetColorLogger := tagLogger.(log.SetColorLogger); isSetColorLogger {
			clogger.SetColor(color.FgCyan)
		}
		logger := log.NewContextLogger(tagLogger)
		wf, err := workflow.NewWorkflow(core, logger, w)
		if err != nil {
			return nil, fmt.Errorf("init workflow %s fail: %s", w.Tag, err)
		}
		core.workflows[w.Tag] = wf
	}
	// Init Listener
	if options.ListenerOptions == nil || len(options.ListenerOptions) == 0 {
		return nil, fmt.Errorf("init listener: no listeners found")
	}
	core.listeners = make(map[string]adapter.Listener)
	for _, l := range options.ListenerOptions {
		if l.Tag == "" {
			return nil, fmt.Errorf("init listener fail: tag is empty")
		}
		if _, ok := core.listeners[l.Tag]; ok {
			return nil, fmt.Errorf("init listener fail: tag %s duplicated", l.Tag)
		}
		tagLogger := log.NewTagLogger(logger, fmt.Sprintf("listener/%s", l.Tag))
		if clogger, isSetColorLogger := tagLogger.(log.SetColorLogger); isSetColorLogger {
			clogger.SetColor(color.FgBlue)
		}
		logger := log.NewContextLogger(tagLogger)
		ler, err := listener.NewListener(ctx, core, logger, l)
		if err != nil {
			return nil, fmt.Errorf("init listener %s fail: %s", l.Tag, err)
		}
		core.listeners[l.Tag] = ler
	}
	return core, nil
}

func (c *Core) Run() error {
	c.logger.Info("core start")
	startTime := time.Now()
	defer c.logger.Info("core close")
	startFatalCtx, startFatalCancel := context.WithCancelCause(c.ctx)
	if c.upstreams != nil {
		for _, u := range c.upstreamArr {
			if fatalStarter, ok := u.(adapter.FatalStarter); ok {
				fatalStarter.WithFatalCloser(startFatalCancel)
			}
			if starter, isStarter := u.(adapter.Starter); isStarter {
				err := starter.Start()
				if err != nil {
					return fmt.Errorf("upstream [%s] start fail: %s", u.Tag(), err)
				}
				c.logger.Info(fmt.Sprintf("upstream [%s] start", u.Tag()))
			}
		}
		defer func() {
			for i := range c.upstreamArr {
				u := c.upstreamArr[len(c.upstreamArr)-1-i]
				if closer, isCloser := u.(adapter.Closer); isCloser {
					err := closer.Close()
					if err != nil {
						c.logger.Error(fmt.Sprintf("upstream [%s] close fail: %s", u.Tag(), err))
					}
					c.logger.Info(fmt.Sprintf("upstream [%s] close", u.Tag()))
				}
			}
		}()
	}
	if c.matchPlugins != nil {
		for _, m := range c.matchPlugins {
			if starter, isStarter := m.(adapter.Starter); isStarter {
				err := starter.Start()
				if err != nil {
					return fmt.Errorf("match plugin [%s] start fail: %s", m.Tag(), err)
				}
				c.logger.Info(fmt.Sprintf("match plugin [%s] start", m.Tag()))
			}
		}
		defer func() {
			for _, m := range c.matchPlugins {
				if closer, isCloser := m.(adapter.Closer); isCloser {
					err := closer.Close()
					if err != nil {
						c.logger.Error(fmt.Sprintf("match plugin [%s] close fail: %s", m.Tag(), err))
					}
					c.logger.Info(fmt.Sprintf("match plugin [%s] close", m.Tag()))
				}
			}
		}()
	}
	if c.execPlugins != nil {
		for _, e := range c.execPlugins {
			if starter, isStarter := e.(adapter.Starter); isStarter {
				err := starter.Start()
				if err != nil {
					return fmt.Errorf("exec plugin [%s] start fail: %s", e.Tag(), err)
				}
				c.logger.Info(fmt.Sprintf("exec plugin [%s] start", e.Tag()))
			}
		}
		defer func() {
			for _, e := range c.execPlugins {
				if closer, isCloser := e.(adapter.Closer); isCloser {
					err := closer.Close()
					if err != nil {
						c.logger.Error(fmt.Sprintf("exec plugin [%s] close fail: %s", e.Tag(), err))
					}
					c.logger.Info(fmt.Sprintf("exec plugin [%s] close", e.Tag()))
				}
			}
		}()
	}
	if c.listeners != nil {
		for _, l := range c.listeners {
			if fatalStarter, ok := l.(adapter.FatalStarter); ok {
				fatalStarter.WithFatalCloser(startFatalCancel)
			}
			if starter, isStarter := l.(adapter.Starter); isStarter {
				err := starter.Start()
				if err != nil {
					return fmt.Errorf("listener [%s] start fail: %s", l.Tag(), err)
				}
				c.logger.Info(fmt.Sprintf("listener [%s] start", l.Tag()))
			}
		}
		defer func() {
			for _, l := range c.listeners {
				if closer, isCloser := l.(adapter.Closer); isCloser {
					err := closer.Close()
					if err != nil {
						c.logger.Error(fmt.Sprintf("listener [%s] close fail: %s", l.Tag(), err))
					}
					c.logger.Info(fmt.Sprintf("listener [%s] close", l.Tag()))
				}
			}
		}()
	}
	if c.apiServer != nil {
		c.apiServer.WithFatalCloser(startFatalCancel)
		err := c.apiServer.Start()
		if err != nil {
			c.logger.Info(fmt.Sprintf("api server start fail: %s", err))
		}
		defer func() {
			err := c.apiServer.Close()
			if err != nil {
				c.logger.Error(fmt.Sprintf("api server close fail: %s", err))
			}
		}()
	}
	c.logger.Info(fmt.Sprintf("core is running, cost %s", time.Since(startTime).String()))
	select {
	case <-startFatalCtx.Done():
		return startFatalCtx.Err()
	case <-c.ctx.Done():
	}
	return nil
}

func (c *Core) GetUpstream(tag string) adapter.Upstream {
	return c.upstreams[tag]
}

func (c *Core) ListUpstream() []adapter.Upstream {
	return c.upstreamArr
}

func (c *Core) GetWorkflow(tag string) adapter.Workflow {
	return c.workflows[tag]
}

func (c *Core) GetMatchPlugin(tag string) adapter.MatchPlugin {
	return c.matchPlugins[tag]
}

func (c *Core) GetExecPlugin(tag string) adapter.ExecPlugin {
	return c.execPlugins[tag]
}

func (c *Core) Handle(ctx context.Context, logger log.ContextLogger, w adapter.Workflow, dnsCtx *adapter.DNSContext) (context.Context, *dns.Msg) {
	ctx = log.AddContextTag(ctx)
	logger.InfoContext(ctx, fmt.Sprintf("receive request from %s, qtype: %s, qname: %s", dnsCtx.ClientIP.String(), dns.TypeToString[dnsCtx.ReqMsg.Question[0].Qtype], dnsCtx.ReqMsg.Question[0].Name))
	if c.apiServer.enableStatistic {
		hook := c.apiServer.upstreamStatisticHook
		dnsCtx.PostUpstreamHook.Append((*adapter.PostUpstreamHookFunc)(&hook))
	}
	w.Exec(ctx, dnsCtx)
	defer func() {
		err := recover()
		if err != nil {
			logger.PrintContext(ctx, "Panic", fmt.Sprintf("panic: %s", err))
			var stackBuf []byte
			n := runtime.Stack(stackBuf, false)
			logger.PrintContext(ctx, "Panic", fmt.Sprintf("stack: %s", stackBuf[:n]))
		}
	}()
	if dnsCtx.RespMsg == nil {
		dnsCtx.RespMsg = &dns.Msg{}
		dnsCtx.RespMsg.SetRcode(dnsCtx.ReqMsg, dns.RcodeServerFailure)
		var name string
		if len(dnsCtx.ReqMsg.Question) > 1 {
			name = dnsCtx.ReqMsg.Question[0].Name
		}
		dnsCtx.RespMsg.Ns = []dns.RR{tools.FakeSOA(name)}
	}
	return ctx, dnsCtx.RespMsg
}
