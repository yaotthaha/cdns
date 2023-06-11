package avg

import "sync"

type Type interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~float32 | ~float64
}

type Avg[T Type] struct {
	totalCount uint64
	avg        float64
	lock       sync.RWMutex
}

func NewAvg[T Type]() *Avg[T] {
	return &Avg[T]{
		totalCount: 0,
		avg:        0,
	}
}

func (a *Avg[T]) Avg(newOne T) float64 {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.totalCount++
	a.avg = (a.avg*float64(a.totalCount-1) + float64(newOne)) / float64(a.totalCount)
	return a.avg
}

func (a *Avg[T]) Load() float64 {
	a.lock.RLock()
	defer a.lock.RUnlock()
	return a.avg
}
