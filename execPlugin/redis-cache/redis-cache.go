package redis_cache

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/lib/tools"
	"github.com/yaotthaha/cdns/log"

	"github.com/go-chi/chi"
	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
)

var (
	_ adapter.ExecPlugin          = (*RedisCache)(nil)
	_ adapter.Starter             = (*RedisCache)(nil)
	_ adapter.Closer              = (*RedisCache)(nil)
	_ adapter.WithContext         = (*RedisCache)(nil)
	_ adapter.WithContextLogger   = (*RedisCache)(nil)
	_ adapter.APIHandler          = (*RedisCache)(nil)
	_ adapter.StatisticAPIHandler = (*RedisCache)(nil)
)

const PluginType = "redis-cache"

func init() {
	adapter.RegisterExecPlugin(PluginType, NewRedisCache)
}

type RedisCache struct {
	tag         string
	ctx         context.Context
	logger      log.ContextLogger
	address     string
	isUnix      bool
	password    string
	database    int
	cleanLock   sync.Mutex
	redisClient *redis.Client
}

type option struct {
	Address  string `yaml:"address"`
	Password string `yaml:"password"`
	Database int    `yaml:"database"`
}

func NewRedisCache(tag string, args map[string]any) (adapter.ExecPlugin, error) {
	r := &RedisCache{
		tag: tag,
	}

	var op option
	err := tools.NewMapStructureDecoderWithResult(&op).Decode(args)
	if err != nil {
		return nil, fmt.Errorf("decode config fail: %s", err)
	}
	if op.Address == "" {
		return nil, fmt.Errorf("address must be not empty")
	}
	address, err := netip.ParseAddrPort(op.Address)
	if err == nil {
		r.address = address.String()
	} else {
		r.address = op.Address
		r.isUnix = true
	}
	r.password = op.Password
	r.database = op.Database

	return r, nil
}

func (r *RedisCache) Tag() string {
	return r.tag
}

func (r *RedisCache) Type() string {
	return PluginType
}

func (r *RedisCache) Start() error {
	if r.isUnix {
		_, err := os.Stat(r.address)
		if err != nil {
			return fmt.Errorf("unix socket error: %s", err)
		}
	}
	opts := &redis.Options{
		Addr:     r.address,
		Password: r.password,
		OnConnect: func(ctx context.Context, cn *redis.Conn) error {
			r.logger.Debug(fmt.Sprintf("connect to redis"))
			return nil
		},
		DB:           r.database,
		DialTimeout:  10 * time.Second,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		PoolSize:     4,
	}
	if r.isUnix {
		opts.Network = "unix"
	}
	c := redis.NewClient(opts)
	_, err := c.Ping(r.ctx).Result()
	if err != nil {
		return fmt.Errorf("ping redis fail: %s", err)
	}
	r.redisClient = c
	return nil
}

func (r *RedisCache) Close() error {
	err := r.redisClient.Close()
	if err != nil {
		return fmt.Errorf("close redis fail: %s", err)
	}
	return nil
}

func (r *RedisCache) WithContext(ctx context.Context) {
	r.ctx = ctx
}

func (r *RedisCache) WithContextLogger(contextLogger log.ContextLogger) {
	r.logger = contextLogger
}

func (r *RedisCache) APIHandler() http.Handler {
	chiRouter := chi.NewRouter()
	chiRouter.Get("/clean", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		go r.cleanCache(req.Context())
	})
	return chiRouter
}

func (r *RedisCache) StatisticAPIHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		result, err := r.redisClient.DBSize(req.Context()).Result()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("{\"total\": %d}", result)))
	})
}

func (r *RedisCache) cleanCache(ctx context.Context) {
	if !r.cleanLock.TryLock() {
		return
	}
	defer r.cleanLock.Unlock()
	r.logger.InfoContext(ctx, "clean cache...")
	err := r.redisClient.FlushAll(r.ctx).Err()
	if err != nil {
		r.logger.ErrorContext(ctx, fmt.Sprintf("clean cache fail: %s", err))
		return
	}
	r.logger.InfoContext(ctx, "clean cache done")
}

func (r *RedisCache) Exec(ctx context.Context, args map[string]any, dnsCtx *adapter.DNSContext) (constant.ReturnMode, error) {
	done := false
	if _, ok := args["store"]; ok {
		if dnsCtx.RespMsg == nil {
			return constant.Continue, nil
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
			r.logger.ErrorContext(ctx, fmt.Sprintf("pack dns msg fail: %s", err))
			return constant.Continue, nil
		}
		dnsStr := hex.EncodeToString(dnsBytes)
		r.logger.DebugContext(ctx, fmt.Sprintf("cache ==> %s", key))
		err = r.redisClient.Set(ctx, key, dnsStr, time.Duration(maxTTL)*time.Second).Err()
		if err != nil {
			r.logger.ErrorContext(ctx, fmt.Sprintf("cache to redis fail: %s", err))
			return constant.Continue, nil
		}
		done = true
	} else if _, ok := args["restore"]; ok {
		key := dnsQuestionToString(dnsCtx.ReqMsg.Question[0])
		dnsStr, err := r.redisClient.Get(ctx, key).Result()
		if err != nil {
			if err == redis.Nil {
				return constant.Continue, nil
			}
			r.logger.ErrorContext(ctx, fmt.Sprintf("get cache from redis fail: %s", err))
			return constant.Continue, nil
		}
		dnsBytes, err := hex.DecodeString(dnsStr)
		if err != nil {
			return constant.Continue, nil
		}
		dnsMsg := &dns.Msg{}
		err = dnsMsg.Unpack(dnsBytes)
		if err != nil {
			return constant.Continue, nil
		}
		dnsMsg.SetReply(dnsCtx.ReqMsg)
		dnsCtx.RespMsg = dnsMsg
		r.logger.DebugContext(ctx, fmt.Sprintf("restore ==> %s", key))
		done = true
	}
	if _, ok := args["return"]; ok && done {
		r.logger.DebugContext(ctx, "return")
		return constant.ReturnAll, nil
	}
	return constant.Continue, nil
}

func dnsQuestionToString(question dns.Question) string {
	return fmt.Sprintf("%s %s %s", question.Name, dns.TypeToString[question.Qtype], dns.ClassToString[question.Qclass])
}
