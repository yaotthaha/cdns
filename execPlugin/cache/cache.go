package cache

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/execPlugin/cache/cachemap"
	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/log"

	"github.com/go-chi/chi"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

const PluginType = "cache"

var (
	_ adapter.ExecPlugin        = (*Cache)(nil)
	_ adapter.Starter           = (*Cache)(nil)
	_ adapter.Closer            = (*Cache)(nil)
	_ adapter.WithContext       = (*Cache)(nil)
	_ adapter.WithContextLogger = (*Cache)(nil)
	_ adapter.APIHandler        = (*Cache)(nil)
)

func init() {
	adapter.RegisterExecPlugin(PluginType, NewCache)
}

type Cache struct {
	tag          string
	ctx          context.Context
	logger       log.ContextLogger
	cleanLock    sync.Mutex
	maxSize      uint64
	dumpFile     string
	dumpInterval time.Duration
	cacheMap     atomic.Pointer[cachemap.CacheMap]
	dumpLock     sync.Mutex
}

type option struct {
	Size         uint64             `yaml:"size"`
	DumpFile     string             `yaml:"dump_file"`
	DumpInterval types.TimeDuration `yaml:"dump_interval"`
}

func NewCache(tag string, args map[string]any) (adapter.ExecPlugin, error) {
	c := &Cache{
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

	if op.Size > 0 {
		c.maxSize = op.Size
	}
	if op.DumpFile != "" {
		c.dumpFile = op.DumpFile
	}
	if op.DumpInterval > 0 {
		c.dumpInterval = time.Duration(op.DumpInterval)
	}

	return c, nil
}

func (c *Cache) Tag() string {
	return c.tag
}

func (c *Cache) Type() string {
	return PluginType
}

func (c *Cache) Start() error {
	if c.dumpFile != "" {
		content, err := os.ReadFile(c.dumpFile)
		if err == nil {
			cacheMap, err := cachemap.RestoreFromBytes(c.ctx, content)
			if err != nil {
				return fmt.Errorf("restore cache map fail: %s", err)
			}
			c.cacheMap.Store(cacheMap)
		} else if os.IsNotExist(err) {
			f, err := os.Create(c.dumpFile)
			if err != nil {
				return fmt.Errorf("create file fail: %s", err)
			}
			f.Close()
			cacheMap := cachemap.New(c.ctx)
			c.cacheMap.Store(cacheMap)
		} else {
			return fmt.Errorf("read file fail: %s", err)
		}
	} else {
		cacheMap := cachemap.New(c.ctx)
		c.cacheMap.Store(cacheMap)
	}
	if c.dumpInterval > 0 {
		go c.dump()
	}
	return nil
}

func (c *Cache) Close() error {
	if c.dumpFile != "" {
		if c.dumpLock.TryLock() {
			cacheMap := c.cacheMap.Load()
			err := c.saveToFile(cacheMap)
			if err != nil {
				c.logger.Error(err.Error())
			}
			c.dumpLock.Unlock()
		}
	}
	return nil
}

func (c *Cache) WithContext(ctx context.Context) {
	c.ctx = ctx
}

func (c *Cache) WithContextLogger(contextLogger log.ContextLogger) {
	c.logger = contextLogger
}

func (c *Cache) APIHandler() http.Handler {
	r := chi.NewRouter()
	r.Get("/clean", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		go c.cleanCache()
	})
	r.Get("/save", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		go c.saveToFileAPI()
	})
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	return r
}

func (c *Cache) cleanCache() {
	if !c.cleanLock.TryLock() {
		return
	}
	defer c.cleanLock.Unlock()
	startTime := time.Now()
	c.logger.Info("clean cache...")
	cacheMap := c.cacheMap.Load()
	if cacheMap == nil {
		return
	}
	cacheMap.CleanAll()
	c.logger.Info("clean cache success, cost: %s", time.Since(startTime).String())
}

func (c *Cache) saveToFileAPI() {
	if !c.dumpLock.TryLock() {
		return
	}
	defer c.dumpLock.Unlock()
	startTime := time.Now()
	c.logger.Info("save cache to file...")
	cacheMap := c.cacheMap.Load()
	err := c.saveToFile(cacheMap)
	if err != nil {
		c.logger.Error(err.Error())
		return
	}
	c.logger.Info("save cache to file success, cost: %s", time.Since(startTime).String())
}

func (c *Cache) Exec(ctx context.Context, args map[string]any, dnsCtx *adapter.DNSContext) bool {
	cacheMap := c.cacheMap.Load()
	if cacheMap == nil {
		return true
	}
	done := false
	if _, ok := args["store"]; ok {
		if dnsCtx.RespMsg == nil {
			return true
		}
		if c.maxSize > 0 {
			if cacheMap.Len() > int(c.maxSize) {
				return true
			}
		}
		key := dnsQuestionToString(dnsCtx.ReqMsg.Question[0])
		var maxTTL uint32
		if dnsCtx.RespMsg.Answer != nil && len(dnsCtx.RespMsg.Answer) > 0 {
			maxTTL = 0
			for _, rr := range dnsCtx.RespMsg.Answer {
				ttl := rr.Header().Ttl
				if maxTTL < ttl {
					maxTTL = ttl
				}
			}
		}
		if maxTTL == 0 {
			maxTTL = 300
		}
		dnsBytes, err := dnsCtx.RespMsg.Pack()
		if err != nil {
			c.logger.ErrorContext(ctx, fmt.Sprintf("pack dns msg fail: %s", err))
			return true
		}
		c.logger.InfoContext(ctx, fmt.Sprintf("cache ==> %s", key))
		cacheMap.Set(key, dnsBytes, time.Now().Add(time.Duration(maxTTL)*time.Second))
		done = true
	} else if _, ok := args["restore"]; ok {
		key := dnsQuestionToString(dnsCtx.ReqMsg.Question[0])
		dnsBytesAny, _, err := cacheMap.Get(key)
		if err != nil {
			return true
		}
		dnsBytes, ok := dnsBytesAny.([]byte)
		if !ok {
			return true
		}
		dnsMsg := &dns.Msg{}
		err = dnsMsg.Unpack(dnsBytes)
		if err != nil {
			return true
		}
		dnsMsg.SetReply(dnsCtx.ReqMsg)
		dnsCtx.RespMsg = dnsMsg
		c.logger.InfoContext(ctx, fmt.Sprintf("restore ==> %s", key))
		done = true
	}
	if _, ok := args["return"]; ok && done {
		c.logger.DebugContext(ctx, "return")
		return false
	}
	return true
}

func (c *Cache) saveToFile(cacheMap *cachemap.CacheMap) error {
	content, err := cacheMap.EncodeToBytes()
	if err != nil {
		return fmt.Errorf("encode cachemap fail: %s", err)
	}
	err = os.WriteFile(c.dumpFile, content, 0o644)
	if err != nil {
		return fmt.Errorf("write file fail: %s", err)
	}
	return nil
}

func (c *Cache) dump() {
	ticker := time.NewTicker(c.dumpInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.dumpLock.Lock()
			cacheMap := c.cacheMap.Load()
			err := c.saveToFile(cacheMap)
			if err != nil {
				c.logger.Error(err.Error())
			}
			c.dumpLock.Unlock()
		case <-c.ctx.Done():
			return
		}
	}
}

func dnsQuestionToString(question dns.Question) string {
	return fmt.Sprintf("%s %s %s", question.Name, dns.TypeToString[question.Qtype], dns.ClassToString[question.Qclass])
}
