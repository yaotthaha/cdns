package adapter

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"

	"github.com/yaotthaha/cdns/constant"
)

type MatchPluginCore interface{}

type MatchPlugin interface {
	Tag() string
	Type() string
	Match(ctx context.Context, args map[string]any, dnsCtx *DNSContext) (match bool, err error) // true: match, false: no match
}

type WithMatchPluginCore interface {
	WithCore(core MatchPluginCore)
}

type ExecPluginCore interface {
	GetWorkflow(tag string) Workflow
	GetUpstream(tag string) Upstream
}

type ExecPlugin interface {
	Tag() string
	Type() string
	Exec(ctx context.Context, args map[string]any, dnsCtx *DNSContext) (returnMode constant.ReturnMode, err error)
}

type WithExecPluginCore interface {
	WithCore(core ExecPluginCore)
}

type APIHandler interface {
	APIHandler() http.Handler
}

type StatisticAPIHandler interface {
	StatisticAPIHandler() http.Handler
}

type CreateMatchPluginFunc func(string, map[string]any) (MatchPlugin, error)

type CreateExecPluginFunc func(string, map[string]any) (ExecPlugin, error)

var (
	matchPluginMap     map[string]CreateMatchPluginFunc
	matchPluginMapLock sync.RWMutex
	execPluginMap      map[string]CreateExecPluginFunc
	execPluginMapLock  sync.RWMutex
)

func init() {
	matchPluginMap = make(map[string]CreateMatchPluginFunc)
	execPluginMap = make(map[string]CreateExecPluginFunc)
}

func RegisterMatchPlugin(typ string, f CreateMatchPluginFunc) {
	matchPluginMapLock.Lock()
	defer matchPluginMapLock.Unlock()
	matchPluginMap[typ] = f
}

func NewMatchPlugin(typ string, tag string, args map[string]any) (MatchPlugin, error) {
	matchPluginMapLock.RLock()
	defer matchPluginMapLock.RUnlock()
	if f, ok := matchPluginMap[typ]; ok {
		return f(tag, args)
	}
	return nil, fmt.Errorf("invalid match plugin type: %s", typ)
}

func GetAllMatchPlugin() []string {
	matchPluginMapLock.RLock()
	defer matchPluginMapLock.RUnlock()
	var ret []string
	for k := range matchPluginMap {
		ret = append(ret, k)
	}
	sort.Slice(ret, func(i, j int) bool {
		return ret[i] < ret[j]
	})
	return ret
}

func RegisterExecPlugin(typ string, f CreateExecPluginFunc) {
	execPluginMapLock.Lock()
	defer execPluginMapLock.Unlock()
	execPluginMap[typ] = f
}

func NewExecPlugin(typ string, tag string, args map[string]any) (ExecPlugin, error) {
	execPluginMapLock.RLock()
	defer execPluginMapLock.RUnlock()
	if f, ok := execPluginMap[typ]; ok {
		return f(tag, args)
	}
	return nil, fmt.Errorf("invalid exec plugin type: %s", typ)
}

func GetAllExecPlugin() []string {
	execPluginMapLock.RLock()
	defer execPluginMapLock.RUnlock()
	var ret []string
	for k := range execPluginMap {
		ret = append(ret, k)
	}
	sort.Slice(ret, func(i, j int) bool {
		return ret[i] < ret[j]
	})
	return ret
}
