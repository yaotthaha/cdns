package safemap

import "sync"

type SafeMap[K comparable, V any] struct {
	m    map[K]V
	lock sync.RWMutex
}

func NewSafeMap[K comparable, V any]() *SafeMap[K, V] {
	return &SafeMap[K, V]{m: make(map[K]V)}
}

func (s *SafeMap[K, V]) Get(key K) (v V) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	v = s.m[key]
	return
}

func (s *SafeMap[K, V]) Set(key K, value V) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.m[key] = value
}
