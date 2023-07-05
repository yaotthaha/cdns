package dialer

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/yaotthaha/cdns/option/upstream"
	"github.com/yaotthaha/cdns/upstream/dialer/socks"
)

var _ NetDialer = (*socks5Dialer)(nil)

type socks5Dialer struct {
	simpleDialer *simpleDialer
	socks5Dialer *socks.Dialer
}

func newSocks5Dialer(options upstream.DialerOptions) (NetDialer, error) {
	simpleDialer, err := newSimpleDialer(options)
	if err != nil {
		return nil, err
	}
	socks5Address, err := netip.ParseAddrPort(options.Socks5.Address)
	if err != nil || !socks5Address.IsValid() {
		return nil, fmt.Errorf("failed to parse socks5_address %s: %v", options.Socks5.Address, err)
	}
	socks5 := socks.NewDialer("tcp", socks5Address.String())
	socks5.ProxyDial = simpleDialer.DialContext
	if options.Socks5.Username != "" && options.Socks5.Password != "" {
		up := socks.UsernamePassword{
			Username: options.Socks5.Username,
			Password: options.Socks5.Password,
		}
		socks5.AuthMethods = []socks.AuthMethod{
			socks.AuthMethodNotRequired,
			socks.AuthMethodUsernamePassword,
		}
		socks5.Authenticate = up.Authenticate
	}
	d := &socks5Dialer{
		simpleDialer: simpleDialer,
		socks5Dialer: socks5,
	}
	return d, nil
}

func (d *socks5Dialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	return d.socks5Dialer.DialContext(ctx, network, address)
}

func (d *socks5Dialer) DialParallel(ctx context.Context, network string, addresses []string) (net.Conn, error) {
	return dialParallel(ctx, d, network, addresses)
}
