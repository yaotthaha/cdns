package adapter

import "context"

type Workflow interface {
	Tag() string
	Exec(context.Context, *DNSContext) (continueExec bool) // true: continue, false: stop
}
