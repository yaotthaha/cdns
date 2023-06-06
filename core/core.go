package core

import (
	"context"
	"fmt"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/execPlugin"
	"github.com/yaotthaha/cdns/listener"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/matchPlugin"
	"github.com/yaotthaha/cdns/option"
	"github.com/yaotthaha/cdns/upstream"
	"github.com/yaotthaha/cdns/workflow"
)

type Core struct {
	ctx          context.Context
	logger       log.Logger
	apiServer    *APIServer
	upstreams    map[string]adapter.Upstream
	workflows    map[string]adapter.Workflow
	matchPlugins map[string]adapter.MatchPlugin
	execPlugins  map[string]adapter.ExecPlugin
	listeners    map[string]adapter.Listener
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
	// Init API Server
	apiServer, err := NewAPIServer(ctx, logger, options.APIOption)
	if err != nil {
		return nil, fmt.Errorf("init api server fail: %s", err)
	}
	core.apiServer = apiServer
	// Init Upstreams
	if options.UpstreamOptions == nil || len(options.UpstreamOptions) == 0 {
		return nil, fmt.Errorf("no upstreams found")
	}
	core.upstreams = make(map[string]adapter.Upstream)
	for _, u := range options.UpstreamOptions {
		if u.Tag == "" {
			return nil, fmt.Errorf("init upstream fail: tag is empty")
		}
		if _, ok := core.upstreams[u.Tag]; ok {
			return nil, fmt.Errorf("init upstream fail: tag %s duplicated", u.Tag)
		}
		up, err := upstream.NewUpstream(ctx, core, logger, u)
		if err != nil {
			return nil, fmt.Errorf("init upstream fail: %s", err)
		}
		core.upstreams[u.Tag] = up
	}
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
			mp.WithContext(ctx)
			mp.WithLogger(log.NewContextLogger(log.NewTagLogger(logger, fmt.Sprintf("match-plugin/%s", mp.Tag()))))
			core.apiServer.MountMatchPlugin(mp)
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
			ep.WithContext(ctx)
			ep.WithLogger(log.NewContextLogger(log.NewTagLogger(logger, fmt.Sprintf("exec-plugin/%s", ep.Tag()))))
			core.apiServer.MountExecPlugin(ep)
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
	if c.upstreams != nil {
		for _, u := range c.upstreams {
			err := u.Start()
			if err != nil {
				return fmt.Errorf("upstream [%s] start fail: %s", u.Tag(), err)
			}
			c.logger.Info(fmt.Sprintf("upstream [%s] start", u.Tag()))
		}
		defer func() {
			for _, u := range c.upstreams {
				err := u.Close()
				if err != nil {
					c.logger.Error(fmt.Sprintf("upstream [%s] close fail: %s", u.Tag(), err))
				}
				c.logger.Info(fmt.Sprintf("upstream [%s] close", u.Tag()))
			}
		}()
	}
	if c.matchPlugins != nil {
		for _, m := range c.matchPlugins {
			err := m.Start()
			if err != nil {
				return fmt.Errorf("match plugin [%s] start fail: %s", m.Tag(), err)
			}
			c.logger.Info(fmt.Sprintf("match plugin [%s] start", m.Tag()))
		}
		defer func() {
			for _, m := range c.matchPlugins {
				err := m.Close()
				if err != nil {
					c.logger.Error(fmt.Sprintf("match plugin [%s] close fail: %s", m.Tag(), err))
				}
				c.logger.Info(fmt.Sprintf("match plugin [%s] close", m.Tag()))
			}
		}()
	}
	if c.execPlugins != nil {
		for _, e := range c.execPlugins {
			err := e.Start()
			if err != nil {
				return fmt.Errorf("exec plugin [%s] start fail: %s", e.Tag(), err)
			}
			c.logger.Info(fmt.Sprintf("exec plugin [%s] start", e.Tag()))
		}
		defer func() {
			for _, e := range c.execPlugins {
				err := e.Close()
				if err != nil {
					c.logger.Error(fmt.Sprintf("exec plugin [%s] close fail: %s", e.Tag(), err))
				}
				c.logger.Info(fmt.Sprintf("exec plugin [%s] close", e.Tag()))
			}
		}()
	}
	if c.listeners != nil {
		for _, l := range c.listeners {
			err := l.Start()
			if err != nil {
				return fmt.Errorf("listener [%s] start fail: %s", l.Tag(), err)
			}
			c.logger.Info(fmt.Sprintf("listener [%s] start", l.Tag()))
		}
		defer func() {
			for _, l := range c.listeners {
				err := l.Close()
				if err != nil {
					c.logger.Error(fmt.Sprintf("listener [%s] close fail: %s", l.Tag(), err))
				}
				c.logger.Info(fmt.Sprintf("listener [%s] close", l.Tag()))
			}
		}()
	}
	if c.apiServer != nil {
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
	<-c.ctx.Done()
	return nil
}

func (c *Core) GetUpstream(tag string) adapter.Upstream {
	return c.upstreams[tag]
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
