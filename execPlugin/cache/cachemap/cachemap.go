package cachemap

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"sync"
	"time"
)

func init() {
	gob.Register(item{})
}

type item struct {
	Key      string
	Value    any
	Deadline time.Time
}

type CacheMap struct {
	ctx      context.Context
	cancel   context.CancelFunc
	callChan chan string
	lock     sync.RWMutex
	m        map[string]*item
}

func New(ctx context.Context) *CacheMap {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	cm := &CacheMap{
		ctx:      ctx,
		cancel:   cancel,
		m:        make(map[string]*item),
		callChan: make(chan string, 4),
	}
	go cm.clean()
	return cm
}

func RestoreFromBytes(ctx context.Context, buf []byte) (*CacheMap, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	cm := &CacheMap{
		ctx:      ctx,
		cancel:   cancel,
		callChan: make(chan string, 4),
	}
	var m map[string]*item
	err := gob.NewDecoder(bytes.NewReader(buf)).Decode(&m)
	if err != nil {
		return nil, err
	}
	cm.m = m
	go cm.clean()
	return cm, nil
}

func (cm *CacheMap) clean() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	defer close(cm.callChan)
	for {
		select {
		case <-ticker.C:
			cm.lock.Lock()
			for _, item := range cm.m {
				if !item.Deadline.IsZero() && time.Now().After(item.Deadline) {
					delete(cm.m, item.Key)
				}
			}
			cm.lock.Unlock()
		case key := <-cm.callChan:
			cm.lock.Lock()
			delete(cm.m, key)
			cm.lock.Unlock()
		case <-cm.ctx.Done():
			return
		}
	}
}

func (cm *CacheMap) Close() {
	cm.cancel()
}

func (cm *CacheMap) Set(key string, value any, deadline time.Time) {
	cm.lock.Lock()
	defer cm.lock.Unlock()
	cm.m[key] = &item{
		Key:      key,
		Value:    value,
		Deadline: deadline,
	}
}

func (cm *CacheMap) Get(key string) (any, time.Time, error) {
	cm.lock.RLock()
	defer cm.lock.RUnlock()
	item, ok := cm.m[key]
	if !ok {
		return nil, time.Time{}, fmt.Errorf("key not found")
	}
	if !item.Deadline.IsZero() && time.Now().After(item.Deadline) {
		cm.callChan <- key
		return nil, time.Time{}, fmt.Errorf("key not found")
	}
	return item.Value, item.Deadline, nil
}

func (cm *CacheMap) Del(key string) {
	cm.lock.Lock()
	defer cm.lock.Unlock()
	delete(cm.m, key)
}

func (cm *CacheMap) Range(f func(key string, value any, deadline time.Time) bool) bool {
	cm.lock.RLock()
	defer cm.lock.RUnlock()
	for _, item := range cm.m {
		if !f(item.Key, item.Value, item.Deadline) {
			return false
		}
	}
	return true
}

func (cm *CacheMap) Len() int {
	cm.lock.RLock()
	defer cm.lock.RUnlock()
	return len(cm.m)
}

func (cm *CacheMap) EncodeToBytes() ([]byte, error) {
	cm.lock.Lock()
	defer cm.lock.Unlock()
	buf := bytes.NewBuffer(nil)
	err := gob.NewEncoder(buf).Encode(cm.m)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
