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
	WithContext(context.Context)
}

type WithLogger interface {
	WithLogger(log.Logger)
}

type WithContextLogger interface {
	WithContextLogger(log.ContextLogger)
}
