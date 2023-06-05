package adapter

import "context"

type Workflow interface {
	Tag() string
	Exec(context.Context, *DNSContext) bool // true: continue, false: stop
}
