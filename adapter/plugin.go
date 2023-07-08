package adapter

import (
	"context"
	"fmt"
	"net/http"
	"sync"
)

type MatchPluginCore interface{}

type MatchPlugin interface {
	Tag() string
	Type() string
	Match(context.Context, map[string]any, *DNSContext) bool // true: match, false: no match
}

type WithMatchPluginCore interface {
	WithCore(MatchPluginCore)
}

type ExecPluginCore interface {
	GetWorkflow(string) Workflow
}

type ExecPlugin interface {
	Tag() string
	Type() string
	Exec(context.Context, map[string]any, *DNSContext) bool // true: continue, false: stop
}

type WithExecPluginCore interface {
	WithCore(ExecPluginCore)
}

type APIHandler interface {
	APIHandler() http.Handler
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
	return ret
}
