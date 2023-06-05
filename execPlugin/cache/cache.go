package cache

import (
	"context"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/log"
)

const PluginType = "cache"

var _ adapter.ExecPlugin = (*Cache)(nil)

func init() {
	adapter.RegisterExecPlugin("cache", NewCache)
}

type Cache struct {
	tag string
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

	return c, nil
}

func (c *Cache) Tag() string {
	return c.tag
}

func (c *Cache) Type() string {
	return PluginType
}

func (c *Cache) Start() error {
	return nil
}

func (c *Cache) Close() error {
	return nil
}

func (c *Cache) WithContext(ctx context.Context) {
	//
}

func (c *Cache) WithLogger(logger log.Logger) {
	// TODO implement me
	panic("implement me")
}

func (c *Cache) Exec(ctx context.Context, m map[string]any, dnsCtx *adapter.DNSContext) bool {
	// TODO implement me
	panic("implement me")
}
