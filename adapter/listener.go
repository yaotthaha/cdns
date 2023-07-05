package adapter

import (
	"context"

	"github.com/yaotthaha/cdns/log"
)

type Listener interface {
	Tag() string
	Type() string
	Context() context.Context
	ContextLogger() log.ContextLogger
	GetWorkflow() Workflow
}
