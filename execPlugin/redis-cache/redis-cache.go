package redis_cache

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/go-chi/chi"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/log"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
	"gopkg.in/yaml.v3"
)

var _ adapter.ExecPlugin = (*RedisCache)(nil)

const PluginType = "redis-cache"

func init() {
	adapter.RegisterExecPlugin(PluginType, NewRedisCache)
}

type RedisCache struct {
	tag         string
	ctx         context.Context
	logger      log.ContextLogger
	address     netip.AddrPort
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
	optionBytes, err := yaml.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("parse args fail: %s", err)
	}
	var op option
	err = yaml.Unmarshal(optionBytes, &op)
	if err != nil {
		return nil, fmt.Errorf("parse args fail: %s", err)
	}
	if op.Address == "" {
		return nil, fmt.Errorf("address must be not empty")
	}
	address, err := netip.ParseAddrPort(op.Address)
	if err != nil {
		return nil, fmt.Errorf("parse address fail: %s", err)
	}
	r.address = address
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
	c := redis.NewClient(&redis.Options{
		Addr:         r.address.String(),
		Password:     r.password,
		DB:           r.database,
		DialTimeout:  10 * time.Second,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		PoolSize:     4,
	})
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

func (r *RedisCache) WithLogger(logger log.ContextLogger) {
	r.logger = logger
}

func (r *RedisCache) WithCore(_ adapter.ExecPluginCore) {
}

func (r *RedisCache) APIHandler() http.Handler {
	chiRouter := chi.NewRouter()
	chiRouter.Get("/clean", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		go r.cleanCache()
	})
	return chiRouter
}

func (r *RedisCache) cleanCache() {
	if !r.cleanLock.TryLock() {
		return
	}
	defer r.cleanLock.Unlock()
	r.logger.Info("clean cache...")
	err := r.redisClient.FlushAll(r.ctx).Err()
	if err != nil {
		r.logger.Error(fmt.Sprintf("clean cache fail: %s", err))
		return
	}
	r.logger.Info("clean cache done")
}

func (r *RedisCache) Exec(ctx context.Context, args map[string]any, dnsCtx *adapter.DNSContext) bool {
	done := false
	if _, ok := args["store"]; ok {
		if dnsCtx.RespMsg == nil {
			return true
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
			return true
		}
		dnsStr := hex.EncodeToString(dnsBytes)
		r.logger.InfoContext(ctx, fmt.Sprintf("cache ==> %s", key))
		err = r.redisClient.Set(ctx, key, dnsStr, time.Duration(maxTTL)*time.Second).Err()
		if err != nil {
			r.logger.ErrorContext(ctx, fmt.Sprintf("cache to redis fail: %s", err))
			return true
		}
		done = true
	} else if _, ok := args["restore"]; ok {
		key := dnsQuestionToString(dnsCtx.ReqMsg.Question[0])
		dnsStr, err := r.redisClient.Get(ctx, key).Result()
		if err != nil {
			if err == redis.Nil {
				return true
			}
			r.logger.ErrorContext(ctx, fmt.Sprintf("get cache from redis fail: %s", err))
			return true
		}
		dnsBytes, err := hex.DecodeString(dnsStr)
		if err != nil {
			return true
		}
		dnsMsg := &dns.Msg{}
		err = dnsMsg.Unpack(dnsBytes)
		if err != nil {
			return true
		}
		dnsMsg.SetReply(dnsCtx.ReqMsg)
		dnsCtx.RespMsg = dnsMsg
		r.logger.InfoContext(ctx, fmt.Sprintf("restore ==> %s", key))
		done = true
	}
	if _, ok := args["return"]; ok && done {
		r.logger.DebugContext(ctx, "return")
		return false
	}
	return true
}

func dnsQuestionToString(question dns.Question) string {
	return fmt.Sprintf("%s %s %s", question.Name, dns.TypeToString[question.Qtype], dns.ClassToString[question.Qclass])
}
