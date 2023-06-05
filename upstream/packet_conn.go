package upstream

import (
	"net"
	"time"
)

type packetConn struct {
	net.Conn
}

func newPacketConn(conn net.Conn) *packetConn {
	return &packetConn{
		Conn: conn,
	}
}

func (p *packetConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, err = p.Conn.Read(b)
	return n, p.Conn.RemoteAddr(), err
}

func (p *packetConn) WriteTo(b []byte, _ net.Addr) (n int, err error) {
	return p.Conn.Write(b)
}

func (p *packetConn) Close() error {
	return p.Conn.Close()
}

func (p *packetConn) LocalAddr() net.Addr {
	return p.Conn.LocalAddr()
}

func (p *packetConn) SetDeadline(t time.Time) error {
	return p.Conn.SetDeadline(t)
}

func (p *packetConn) SetReadDeadline(t time.Time) error {
	return p.Conn.SetReadDeadline(t)
}

func (p *packetConn) SetWriteDeadline(t time.Time) error {
	return p.Conn.SetWriteDeadline(t)
}
