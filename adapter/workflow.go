package adapter

import (
	"context"

	"github.com/yaotthaha/cdns/constant"
)

type Workflow interface {
	Tag() string
	Exec(ctx context.Context, dnsCtx *DNSContext) constant.ReturnMode
}
