package adapter

import (
	"context"

	"github.com/yaotthaha/cdns/log"
)

type Listener interface {
	Tag() string
	Type() string
	Start() error
	Close() error
	Context() context.Context
	ContextLogger() log.ContextLogger
	GetWorkflow() Workflow
}
