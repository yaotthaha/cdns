package types

import "sync/atomic"

type AtomicValue[T any] struct {
	value atomic.Value
}

func (v *AtomicValue[T]) Load() (val T) {
	value := v.value.Load()
	if value != nil {
		val = value.(T)
	}
	return
}

func (v *AtomicValue[T]) Store(val T) {
	v.value.Store(val)
}

func (v *AtomicValue[T]) Swap(new T) (old T) {
	oldValue := v.value.Swap(new)
	if oldValue != nil {
		old = oldValue.(T)
	}
	return
}

func (v *AtomicValue[T]) CompareAndSwap(old, new T) (swapped bool) {
	return v.value.CompareAndSwap(old, new)
}
