package types

import (
	"sync"
)

type SafeValue[T any] struct {
	value T
	lock  sync.Mutex
}

func (s *SafeValue[T]) Store(value T) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.value = value
}

func (s *SafeValue[T]) Load() (value T) {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.value
}

func (s *SafeValue[T]) Swap(value T) T {
	s.lock.Lock()
	defer s.lock.Unlock()
	old := s.value
	s.value = value
	return old
}
