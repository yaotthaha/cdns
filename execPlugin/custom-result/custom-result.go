package custom_result

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/lib/tools"
	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/log"

	"github.com/go-chi/chi"
	"github.com/miekg/dns"
)

const PluginType = "custom-result"

func init() {
	adapter.RegisterExecPlugin(PluginType, NewCustomResult)
}

var (
	_ adapter.ExecPlugin        = (*CustomResult)(nil)
	_ adapter.Starter           = (*CustomResult)(nil)
	_ adapter.WithContextLogger = (*CustomResult)(nil)
	_ adapter.APIHandler        = (*CustomResult)(nil)
)

type CustomResult struct {
	tag    string
	logger log.ContextLogger

	fileList         []string
	fileResultDNSMap atomic.Pointer[map[string]*dns.Msg]
	resultMap        map[string]string
	resultDNSMap     map[string]*dns.Msg

	reloadLock sync.Mutex
}

type option struct {
	Result map[string]string      `yaml:"result"`
	File   types.Listable[string] `yaml:"file"`
}

func NewCustomResult(tag string, args map[string]any) (adapter.ExecPlugin, error) {
	c := &CustomResult{
		tag: tag,
	}

	var op option
	err := tools.NewMapStructureDecoderWithResult(&op).Decode(args)
	if err != nil {
		return nil, fmt.Errorf("decode config fail: %s", err)
	}
	if op.Result == nil || len(op.Result) == 0 {
		return nil, fmt.Errorf("result is nil")
	}
	c.resultMap = op.Result
	if op.File != nil && len(op.File) > 0 {
		c.fileList = op.File
		sort.Slice(c.fileList, func(i, j int) bool {
			return c.fileList[i] < c.fileList[j]
		})
	}

	return c, nil
}

func (c *CustomResult) Tag() string {
	return c.tag
}

func (c *CustomResult) Type() string {
	return PluginType
}

func (c *CustomResult) WithContextLogger(logger log.ContextLogger) {
	c.logger = logger
}

func (c *CustomResult) Start() error {
	c.resultDNSMap = make(map[string]*dns.Msg)
	for k, v := range c.resultMap {
		vv, err := hex.DecodeString(v)
		if err != nil {
			return fmt.Errorf("decode result fail: %s", err)
		}
		dnsMsg := new(dns.Msg)
		err = dnsMsg.Unpack(vv)
		if err != nil {
			return fmt.Errorf("decode result fail: %s", err)
		}
		k = strings.TrimSpace(k)
		c.resultDNSMap[k] = dnsMsg
	}
	if c.fileList != nil {
		resultDNSMap, err := c.readFile()
		if err != nil {
			return err
		}
		c.fileResultDNSMap.Store(resultDNSMap)
	}
	return nil
}

func (c *CustomResult) APIHandler() http.Handler {
	chiRouter := chi.NewRouter()
	chiRouter.Get("/reload", func(w http.ResponseWriter, r *http.Request) {
		go c.reloadFile(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})
	return chiRouter
}

func (c *CustomResult) Exec(_ context.Context, _ map[string]any, dnsCtx *adapter.DNSContext) (returnMode constant.ReturnMode, err error) {
	reqMsgQ := dnsCtx.ReqMsg.Question[0]
	name := reqMsgQ.Name
	if dns.IsFqdn(name) {
		name = name[:len(name)-1]
	}
	key := fmt.Sprintf("%s %s", name, dns.ClassToString[reqMsgQ.Qtype])
	value := c.resultDNSMap[key]
	if value == nil {
		fileResultDNSMap := c.fileResultDNSMap.Load()
		if fileResultDNSMap == nil {
			return constant.Continue, nil
		}
		value = (*fileResultDNSMap)[key]
	}
	if value == nil {
		return constant.Continue, nil
	}
	newRespMsg := new(dns.Msg)
	value.CopyTo(newRespMsg)
	newRespMsg.SetReply(dnsCtx.ReqMsg)
	dnsCtx.RespMsg = newRespMsg
	return constant.Continue, nil
}

func (c *CustomResult) readFile() (*map[string]*dns.Msg, error) {
	if c.fileList != nil {
		resultDNSMap := new(map[string]*dns.Msg)
		*resultDNSMap = make(map[string]*dns.Msg)
		resultMap := make(map[string]string)
		for _, file := range c.fileList {
			contentBytes, err := os.ReadFile(file)
			if err != nil {
				return nil, fmt.Errorf("read file %s fail: %s", file, err)
			}
			contentBytes = bytes.ReplaceAll(contentBytes, []byte("\r"), []byte("\n"))
			contentBytes = bytes.ReplaceAll(contentBytes, []byte("\n\n"), []byte("\n"))
			contentList := strings.Split(string(contentBytes), "\n")
			for _, content := range contentList {
				content = strings.TrimSpace(content)
				contents := strings.SplitN(content, " ", 3)
				if len(contents) != 3 {
					return nil, fmt.Errorf("file %s format error", file)
				}
				domain := fmt.Sprintf("%s %s", contents[0], contents[1])
				resultMap[domain] = contents[2]
			}
		}
		for k, v := range resultMap {
			vv, err := hex.DecodeString(v)
			if err != nil {
				return nil, fmt.Errorf("decode result %s fail: %s", k, err)
			}
			dnsMsg := new(dns.Msg)
			err = dnsMsg.Unpack(vv)
			if err != nil {
				return nil, fmt.Errorf("decode result %s fail: %s", k, err)
			}
			k = strings.TrimSpace(k)
			(*resultDNSMap)[k] = dnsMsg
		}
		return resultDNSMap, nil
	}
	return nil, nil
}

func (c *CustomResult) reloadFile(ctx context.Context) {
	if !c.reloadLock.TryLock() {
		return
	}
	defer c.reloadLock.Unlock()
	c.logger.InfoContext(ctx, "reload file...")
	resultDNSMap, err := c.readFile()
	if err != nil {
		c.logger.ErrorContext(ctx, fmt.Sprintf("reload file fail: %s", err))
		return
	}
	c.fileResultDNSMap.Store(resultDNSMap)
	c.logger.InfoContext(ctx, "reload file success")
}
