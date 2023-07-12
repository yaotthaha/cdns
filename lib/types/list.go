package types

import "sync"

type List[T comparable] struct {
	arr  []T
	lock sync.RWMutex
}

func NewList[T comparable]() *List[T] {
	return &List[T]{
		arr: make([]T, 0),
	}
}

func (l *List[T]) Append(v T) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.arr = append(l.arr, v)
}

func (l *List[T]) GetLast() (v T) {
	l.lock.Lock()
	defer l.lock.Unlock()
	if len(l.arr) > 0 {
		v = l.arr[len(l.arr)-1]
	}
	return
}

func (l *List[T]) DelLast() (v T) {
	l.lock.Lock()
	defer l.lock.Unlock()
	if len(l.arr) > 0 {
		v = l.arr[len(l.arr)-1]
		l.arr = l.arr[:len(l.arr)-1]
	}
	return
}

func (l *List[T]) DelHeadV(v T) {
	l.lock.Lock()
	defer l.lock.Unlock()
	for i, _v := range l.arr {
		if _v == v {
			l.arr = append(l.arr[:i], l.arr[i+1:]...)
			break
		}
	}
}

func (l *List[T]) DelTailV(v T) {
	l.lock.Lock()
	defer l.lock.Unlock()
	for i := range l.arr {
		_v := l.arr[len(l.arr)-1-i]
		if _v == v {
			l.arr = append(l.arr[:len(l.arr)-1-i], l.arr[len(l.arr)-i:]...)
			break
		}
	}
}

func (l *List[T]) Len() int {
	l.lock.RLock()
	defer l.lock.RUnlock()
	return len(l.arr)
}

func (l *List[T]) Range(f func(index int, value T) bool) {
	l.lock.RLock()
	defer l.lock.RUnlock()
	for i, v := range l.arr {
		if !f(i, v) {
			break
		}
	}
}

func (l *List[T]) Clone() *List[T] {
	l.lock.RLock()
	defer l.lock.RUnlock()
	newL := &List[T]{
		arr: make([]T, len(l.arr)),
	}
	copy(newL.arr, l.arr)
	return newL
}
