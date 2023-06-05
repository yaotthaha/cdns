//go:build darwin

package control

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

func bindToInterface(conn syscall.RawConn, network string, interfaceName string, interfaceIndex int) error {
	if interfaceIndex == -1 {
		return nil
	}
	var inErr error
	err := conn.Control(func(fd uintptr) {
		switch network {
		case "4":
			inErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, interfaceIndex)
		default:
			inErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, interfaceIndex)
		}
	})
	if inErr != nil {
		if err != nil {
			return fmt.Errorf("errors: %s, and %s", inErr, err)
		}
		return inErr
	}
	return err
}
