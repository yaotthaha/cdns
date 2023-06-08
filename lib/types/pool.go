package types

import "sync"

type SyncPool[T any] struct {
	sync.Pool
}

func (p *SyncPool[T]) New(f func() T) {
	p.Pool.New = func() any {
		return f()
	}
}

func (p *SyncPool[T]) Get() (v T) {
	val := p.Pool.Get()
	v = val.(T)
	return
}

func (p *SyncPool[T]) Put(v T) {
	p.Pool.Put(v)
}
