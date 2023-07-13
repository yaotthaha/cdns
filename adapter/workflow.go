package adapter

import (
	"context"

	"github.com/yaotthaha/cdns/constant"
)

type Workflow interface {
	Tag() string
	Exec(context.Context, *DNSContext) (returnMode constant.ReturnMode)
}
