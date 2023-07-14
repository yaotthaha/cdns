package script

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/lib/tools"
	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/log"

	"github.com/miekg/dns"
)

const PluginType = "script"

func init() {
	adapter.RegisterExecPlugin(PluginType, NewScript)
}

var (
	_ adapter.ExecPlugin        = (*Script)(nil)
	_ adapter.WithContext       = (*Script)(nil)
	_ adapter.WithContextLogger = (*Script)(nil)
	_ adapter.Starter           = (*Script)(nil)
	_ adapter.Closer            = (*Script)(nil)
)

type Script struct {
	tag    string
	logger log.ContextLogger
	ctx    context.Context
	cancel context.CancelFunc

	cmd  string
	args []string
	env  map[string]string

	bufferPool *sync.Pool
}

type option struct {
	Cmd  string                 `config:"cmd"`
	Args types.Listable[string] `config:"args"`
	Env  map[string]string      `config:"env"`
}

func NewScript(tag string, args map[string]any) (adapter.ExecPlugin, error) {
	s := &Script{
		tag: tag,
	}

	var op option
	err := tools.NewMapStructureDecoderWithResult(&op).Decode(args)
	if err != nil {
		return nil, fmt.Errorf("decode config fail: %s", err)
	}
	if op.Cmd == "" {
		return nil, fmt.Errorf("cmd is empty")
	}
	s.cmd = op.Cmd
	if op.Args != nil && len(op.Args) > 0 {
		s.args = op.Args
	}
	if op.Env != nil && len(op.Env) > 0 {
		s.env = op.Env
	}

	return s, nil
}

func (s *Script) Tag() string {
	return s.tag
}

func (s *Script) Type() string {
	return PluginType
}

func (s *Script) WithContext(ctx context.Context) {
	s.ctx, s.cancel = context.WithCancel(ctx)
}

func (s *Script) WithContextLogger(logger log.ContextLogger) {
	s.logger = logger
}

func (s *Script) Start() error {
	s.bufferPool = &sync.Pool{
		New: func() any {
			return bytes.NewBuffer(nil)
		},
	}
	return nil
}

func (s *Script) Close() error {
	s.cancel()
	return nil
}

func (s *Script) runScript(logTag string, env map[string]string) {
	ctx := log.AddContextTagFromTag(s.ctx, logTag)
	var cmd *exec.Cmd
	if s.args != nil && len(s.args) > 0 {
		cmd = exec.CommandContext(ctx, s.cmd, s.args...)
	} else {
		cmd = exec.CommandContext(ctx, s.cmd)
	}
	envMap := make(map[string]string)
	if s.env != nil {
		for k, v := range s.env {
			envMap[k] = v
		}
	}
	if env != nil {
		for k, v := range env {
			envMap[k] = v
		}
	}
	if len(envMap) > 0 {
		cmd.Env = make([]string, 0)
		for k, v := range envMap {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	var (
		stdout = s.bufferPool.Get().(*bytes.Buffer)
		stderr = s.bufferPool.Get().(*bytes.Buffer)
	)
	defer func() {
		stdout.Reset()
		stderr.Reset()
		s.bufferPool.Put(stdout)
		s.bufferPool.Put(stderr)
	}()
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if err != nil {
		s.logger.Error(fmt.Sprintf("run script error: %s", err.Error()))
	} else {
		s.logger.Debug("run script success")
	}
	if stdout.Len() > 0 {
		stdoutStr := stdout.String()
		stdoutStr = strings.TrimRightFunc(stdoutStr, func(r rune) bool {
			return r == '\n' || r == '\r'
		})
		s.logger.Debug(fmt.Sprintf("script stdout: %s", stdoutStr))
	}
	if stderr.Len() > 0 {
		stderrStr := stderr.String()
		stderrStr = strings.TrimRightFunc(stderrStr, func(r rune) bool {
			return r == '\n' || r == '\r'
		})
		s.logger.Debug(fmt.Sprintf("script stderr: %s", stderrStr))
	}
}

func (s *Script) Exec(ctx context.Context, args map[string]any, dnsCtx *adapter.DNSContext) (constant.ReturnMode, error) {
	s.logger.DebugContext(ctx, fmt.Sprintf("run script"))
	envMap := readEnvFromDNSCtx(dnsCtx)
	for k, v := range args {
		switch vv := v.(type) {
		case string:
			envMap["CDNS_ARGS_"+k] = vv
		case fmt.Stringer:
			envMap["CDNS_ARGS_"+k] = vv.String()
		case int:
			envMap["CDNS_ARGS_"+k] = fmt.Sprintf("%d", vv)
		case int8:
			envMap["CDNS_ARGS_"+k] = fmt.Sprintf("%d", vv)
		case int16:
			envMap["CDNS_ARGS_"+k] = fmt.Sprintf("%d", vv)
		case int32:
			envMap["CDNS_ARGS_"+k] = fmt.Sprintf("%d", vv)
		case int64:
			envMap["CDNS_ARGS_"+k] = fmt.Sprintf("%d", vv)
		case uint:
			envMap["CDNS_ARGS_"+k] = fmt.Sprintf("%d", vv)
		case uint8:
			envMap["CDNS_ARGS_"+k] = fmt.Sprintf("%d", vv)
		case uint16:
			envMap["CDNS_ARGS_"+k] = fmt.Sprintf("%d", vv)
		case uint32:
			envMap["CDNS_ARGS_"+k] = fmt.Sprintf("%d", vv)
		case uint64:
			envMap["CDNS_ARGS_"+k] = fmt.Sprintf("%d", vv)
		case float32:
			envMap["CDNS_ARGS_"+k] = fmt.Sprintf("%f", vv)
		case float64:
			envMap["CDNS_ARGS_"+k] = fmt.Sprintf("%f", vv)
		case bool:
			envMap["CDNS_ARGS_"+k] = fmt.Sprintf("%t", vv)
		}
	}
	go s.runScript(log.GetContextTag(ctx), envMap)
	return constant.Continue, nil
}

func readEnvFromDNSCtx(dnsCtx *adapter.DNSContext) map[string]string {
	envMap := make(map[string]string)
	if dnsCtx.Listener != "" {
		envMap["CDNS_LISTENER"] = dnsCtx.Listener
	}
	if dnsCtx.ClientIP.IsValid() {
		envMap["CDNS_CLIENT_IP"] = dnsCtx.ClientIP.String()
	}
	if dnsCtx.ReqMsg != nil {
		q := dnsCtx.ReqMsg.Question[0]
		name := q.Name
		if dns.IsFqdn(name) {
			name = name[:len(name)-1]
		}
		envMap["CDNS_REQ_NAME"] = name
		envMap["CDNS_REQ_TYPE"] = dns.TypeToString[q.Qtype]
	}
	if dnsCtx.Mark >= 0 {
		envMap["CDNS_MARK"] = fmt.Sprintf("%d", dnsCtx.Mark)
	}
	if dnsCtx.MetaData.Len() > 0 {
		dnsCtx.MetaData.Range(func(key string, value types.CloneableValue) bool {
			if vv, ok := value.(fmt.Stringer); ok {
				envMap["CDNS_META_"+strings.ToUpper(key)] = vv.String()
			}
			return true
		})
	}
	return envMap
}
