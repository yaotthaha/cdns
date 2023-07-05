//go:build windows

package control

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	IP_UNICAST_IF   = 31
	IPV6_UNICAST_IF = 31
)

func BindToInterface(conn syscall.RawConn, network string, interfaceName string, interfaceIndex int) error {
	var inErr error
	err := conn.Control(func(fd uintptr) {
		handle := syscall.Handle(fd)
		switch network {
		case "4":
			var bytes [4]byte
			binary.BigEndian.PutUint32(bytes[:], uint32(interfaceIndex))
			idx := *(*uint32)(unsafe.Pointer(&bytes[0]))
			inErr = syscall.SetsockoptInt(handle, syscall.IPPROTO_IP, IP_UNICAST_IF, int(idx))
		default:
			inErr = syscall.SetsockoptInt(handle, syscall.IPPROTO_IPV6, IPV6_UNICAST_IF, interfaceIndex)
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
