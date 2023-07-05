package dialer

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/option/upstream"
)

type NetDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	DialParallel(ctx context.Context, network string, addresses []string) (net.Conn, error)
}

func NewNetDialer(options upstream.DialerOptions) (NetDialer, error) {
	if options.Socks5 != nil {
		return newSocks5Dialer(options)
	} else {
		return newSimpleDialer(options)
	}
}

type dialResult struct {
	conn net.Conn
	err  error
}

func dialParallel(ctx context.Context, dialer NetDialer, network string, addresses []string) (net.Conn, error) {
	if addresses == nil || len(addresses) == 0 {
		return nil, fmt.Errorf("addresses is empty")
	}
	if len(addresses) == 1 {
		return dialer.DialContext(ctx, network, addresses[0])
	}
	var saveResult types.AtomicValue[*dialResult]
	var saveErr types.AtomicValue[error]
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	wg := sync.WaitGroup{}
	for _, address := range addresses {
		wg.Add(1)
		go func(address string) {
			defer wg.Done()
			conn, err := dialer.DialContext(ctx, network, address)
			if err != nil {
				saveErr.CompareAndSwap(nil, err)
				return
			}
			if !saveResult.CompareAndSwap(nil, &dialResult{}) {
				conn.Close()
			} else {
				cancel()
			}
		}(address)
	}
	go func() {
		wg.Wait()
		cancel()
	}()
	<-ctx.Done()
	conn := saveResult.Load()
	if conn != nil {
		return conn.conn, nil
	}
	err := saveErr.Load()
	if err != nil {
		err = ctx.Err()
	}
	return nil, err
}
