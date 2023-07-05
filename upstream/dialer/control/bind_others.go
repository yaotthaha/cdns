//go:build !(linux || windows || darwin)

package control

func BindToInterface(conn syscall.RawConn, _ string, interfaceName string, interfaceIndex int) error {
	return nil
}
