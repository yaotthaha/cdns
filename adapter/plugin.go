package adapter

import (
	"context"
	"fmt"
	"sync"

	"github.com/yaotthaha/cdns/log"
)

type MatchPlugin interface {
	Tag() string
	Type() string
	Start() error
	Close() error
	WithContext(context.Context)
	WithLogger(log.Logger)
	Match(context.Context, map[string]any, *DNSContext) bool // true: match, false: no match
}

type ExecPlugin interface {
	Tag() string
	Type() string
	Start() error
	Close() error
	WithContext(context.Context)
	WithLogger(log.Logger)
	Exec(context.Context, map[string]any, *DNSContext) bool // true: continue, false: stop
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
