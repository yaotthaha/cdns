package adapter

import (
	"context"

	"github.com/yaotthaha/cdns/log"
)

type Starter interface {
	Start() error
}

type Closer interface {
	Close() error
}

type WithContext interface {
	WithContext(ctx context.Context)
}

type WithLogger interface {
	WithLogger(logger log.Logger)
}

type WithContextLogger interface {
	WithContextLogger(logger log.ContextLogger)
}
