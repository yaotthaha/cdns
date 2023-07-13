package script

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/log"

	"gopkg.in/yaml.v3"
)

const PluginType = "script"

func init() {
	adapter.RegisterMatchPlugin(PluginType, NewScript)
}

var (
	_ adapter.MatchPlugin       = (*Script)(nil)
	_ adapter.Starter           = (*Script)(nil)
	_ adapter.WithContext       = (*Script)(nil)
	_ adapter.WithContextLogger = (*Script)(nil)
)

type Script struct {
	tag    string
	ctx    context.Context
	logger log.ContextLogger

	option option
	cache  types.AtomicValue[*string]
}

type option struct {
	Cmd         string                 `yaml:cmd`
	Args        types.Listable[string] `yaml:args`
	Env         map[string]string      `yaml:env`
	Timeout     types.TimeDuration     `yaml:timeout`
	EnableCache bool                   `yaml:enable-cache`
}

func NewScript(tag string, args map[string]any) (adapter.MatchPlugin, error) {
	s := &Script{
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
	if op.Cmd == "" {
		return nil, fmt.Errorf("cmd is nil")
	}
	if op.Timeout <= 0 {
		op.Timeout = types.TimeDuration(200 * time.Millisecond)
	}
	s.option = op

	return s, nil
}

func (s *Script) Tag() string {
	return s.tag
}

func (s *Script) Type() string {
	return PluginType
}

func (s *Script) WithContextLogger(logger log.ContextLogger) {
	s.logger = logger
}

func (s *Script) WithContext(ctx context.Context) {
	s.ctx = ctx
}

func (s *Script) newCommand(ctx context.Context) *exec.Cmd {
	var cmd *exec.Cmd
	if s.option.Args != nil && len(s.option.Args) > 0 {
		cmd = exec.CommandContext(ctx, s.option.Cmd, s.option.Args...)
	} else {
		cmd = exec.CommandContext(ctx, s.option.Cmd)
	}
	if s.option.Env != nil && len(s.option.Env) > 0 {
		cmd.Env = make([]string, 0)
		for k, v := range s.option.Env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}
	return cmd
}

func (s *Script) runWrapper(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(s.option.Timeout))
	defer cancel()
	cmd := s.newCommand(ctx)
	var (
		stdout = bytes.NewBuffer(nil)
		stderr = io.Discard
	)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if err != nil {
		err = fmt.Errorf("run fail: %s", err)
		return "", err
	}
	stdoutStr := stdout.String()
	stdoutStr = strings.TrimSpace(stdoutStr)
	return stdoutStr, nil
}

func (s *Script) runOrReadCache(ctx context.Context) (string, error) {
	if !s.option.EnableCache {
		return s.runWrapper(ctx)
	}
	strPointer := s.cache.Load()
	if strPointer == nil {
		str, err := s.runWrapper(ctx)
		if err != nil {
			return "", err
		}
		s.cache.Store(&str)
		return str, nil
	} else {
		return *strPointer, nil
	}
}

func (s *Script) keepRun() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.runOrReadCache(s.ctx)
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *Script) Start() error {
	if s.option.EnableCache {
		_, err := s.runOrReadCache(s.ctx)
		if err != nil {
			return err
		}
		go s.keepRun()
	}
	return nil
}

func (s *Script) Match(ctx context.Context, args map[string]any, dnsCtx *adapter.DNSContext) (bool, error) {
	var match string
	matchAny, ok := args["match"]
	if !ok {
		err := fmt.Errorf("match string not found")
		s.logger.ErrorContext(ctx, err)
		return false, err
	}
	match, ok = matchAny.(string)
	if !ok {
		err := fmt.Errorf("match string not found")
		s.logger.ErrorContext(ctx, err)
		return false, err
	}
	str, err := s.runOrReadCache(ctx)
	if err != nil {
		err = fmt.Errorf("result not found: %s", err)
		s.logger.ErrorContext(ctx, err)
		return false, err
	}
	return match == str, nil
}
