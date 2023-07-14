package types

import (
	"sync"
)

type CloneableValue interface {
	Clone() CloneableValue
	Value() any
}

type BasicCloneableValue interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~float32 | ~float64 | ~complex64 | ~complex128 | ~string
}

func cloneValue[T BasicCloneableValue](value T) (v T) {
	v = value
	return v
}

type _cloneableValueImpl[T BasicCloneableValue] struct {
	value T
}

func NewCloneableValue[T BasicCloneableValue](value T) CloneableValue {
	return &_cloneableValueImpl[T]{
		value: value,
	}
}

func (c *_cloneableValueImpl[T]) Clone() CloneableValue {
	return NewCloneableValue(cloneValue(c.value))
}

func (c *_cloneableValueImpl[T]) Value() any {
	return c.value
}

type CloneableSyncMap[K comparable, V CloneableValue] struct {
	m sync.Map
}

func (cm *CloneableSyncMap[K, V]) Load(key K) (value V, ok bool) {
	var valueAny any
	valueAny, ok = cm.m.Load(key)
	if valueAny != nil {
		value = valueAny.(V)
	}
	return
}

func (cm *CloneableSyncMap[K, V]) Store(key K, value V) {
	cm.m.Store(key, value)
}

func (cm *CloneableSyncMap[K, V]) LoadOrStore(key K, value V) (actual V, loaded bool) {
	var atcualAny any
	atcualAny, loaded = cm.m.LoadOrStore(key, value)
	if atcualAny != nil {
		actual = atcualAny.(V)
	}
	return
}

func (cm *CloneableSyncMap[K, V]) LoadAndDelete(key K) (value V, loaded bool) {
	var valueAny any
	valueAny, loaded = cm.m.LoadAndDelete(key)
	if valueAny != nil {
		value = valueAny.(V)
	}
	return
}

func (cm *CloneableSyncMap[K, V]) Delete(key K) {
	cm.m.Delete(key)
}

func (cm *CloneableSyncMap[K, V]) Swap(key K, value V) (previous V, loaded bool) {
	var previousAny any
	previousAny, loaded = cm.m.Swap(key, value)
	if previousAny != nil {
		previous = previousAny.(V)
	}
	return
}

func (cm *CloneableSyncMap[K, V]) CompareAndSwap(key K, old V, new V) bool {
	return cm.m.CompareAndSwap(key, old, new)
}

func (cm *CloneableSyncMap[K, V]) CompareAndDelete(key K, old V) (deleted bool) {
	return cm.m.CompareAndDelete(key, old)
}

func (cm *CloneableSyncMap[K, V]) Range(f func(key K, value V) bool) {
	cm.m.Range(func(keyAny any, valueAny any) bool {
		var key K
		var value V
		if keyAny != nil {
			key = keyAny.(K)
		}
		if valueAny != nil {
			value = valueAny.(V)
		}
		return f(key, value)
	})
}

func (cm *CloneableSyncMap[K, V]) Len() int {
	var length int
	cm.m.Range(func(keyAny any, valueAny any) bool {
		length++
		return true
	})
	return length
}

func (cm *CloneableSyncMap[K, V]) Clone() *CloneableSyncMap[K, V] {
	var cmClone CloneableSyncMap[K, V]
	cm.m.Range(func(keyAny any, valueAny any) bool {
		cmClone.m.Store(keyAny, valueAny)
		return true
	})
	return &cmClone
}

func (cm *CloneableSyncMap[K, V]) Reset() {
	cm.m.Range(func(keyAny any, valueAny any) bool {
		cm.m.Delete(keyAny)
		return true
	})
}

type SyncMap[K comparable, V any] struct {
	m sync.Map
}

func (cm *SyncMap[K, V]) Load(key K) (value V, ok bool) {
	var valueAny any
	valueAny, ok = cm.m.Load(key)
	if valueAny != nil {
		value = valueAny.(V)
	}
	return
}

func (cm *SyncMap[K, V]) Store(key K, value V) {
	cm.m.Store(key, value)
}

func (cm *SyncMap[K, V]) LoadOrStore(key K, value V) (actual V, loaded bool) {
	var atcualAny any
	atcualAny, loaded = cm.m.LoadOrStore(key, value)
	if atcualAny != nil {
		actual = atcualAny.(V)
	}
	return
}

func (cm *SyncMap[K, V]) LoadAndDelete(key K) (value V, loaded bool) {
	var valueAny any
	valueAny, loaded = cm.m.LoadAndDelete(key)
	if valueAny != nil {
		value = valueAny.(V)
	}
	return
}

func (cm *SyncMap[K, V]) Delete(key K) {
	cm.m.Delete(key)
}

func (cm *SyncMap[K, V]) Swap(key K, value V) (previous V, loaded bool) {
	var previousAny any
	previousAny, loaded = cm.m.Swap(key, value)
	if previousAny != nil {
		previous = previousAny.(V)
	}
	return
}

func (cm *SyncMap[K, V]) CompareAndSwap(key K, old V, new V) bool {
	return cm.m.CompareAndSwap(key, old, new)
}

func (cm *SyncMap[K, V]) CompareAndDelete(key K, old V) (deleted bool) {
	return cm.m.CompareAndDelete(key, old)
}

func (cm *SyncMap[K, V]) Range(f func(key K, value V) bool) {
	cm.m.Range(func(keyAny any, valueAny any) bool {
		var key K
		var value V
		if keyAny != nil {
			key = keyAny.(K)
		}
		if valueAny != nil {
			value = valueAny.(V)
		}
		return f(key, value)
	})
}

func (cm *SyncMap[K, V]) Len() int {
	var length int
	cm.m.Range(func(keyAny any, valueAny any) bool {
		length++
		return true
	})
	return length
}
