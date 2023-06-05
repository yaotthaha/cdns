package connpool

import (
	"net"
	"time"
)

type timeConn struct {
	conn       net.Conn
	lastActive time.Time
}

func newTimeConn(conn net.Conn) *timeConn {
	return &timeConn{
		conn:       conn,
		lastActive: time.Now(),
	}
}

func (c *timeConn) refresh() {
	c.lastActive = time.Now()
}

func (c *timeConn) Read(b []byte) (int, error) {
	c.refresh()
	defer c.refresh()
	return c.conn.Read(b)
}

func (c *timeConn) Write(b []byte) (int, error) {
	c.refresh()
	defer c.refresh()
	return c.conn.Write(b)
}

func (c *timeConn) Close() error {
	return c.conn.Close()
}

func (c *timeConn) LocalAddr() net.Addr {
	c.refresh()
	defer c.refresh()
	return c.conn.LocalAddr()
}

func (c *timeConn) RemoteAddr() net.Addr {
	c.refresh()
	defer c.refresh()
	return c.conn.RemoteAddr()
}

func (c *timeConn) SetDeadline(t time.Time) error {
	c.refresh()
	defer c.refresh()
	return c.conn.SetDeadline(t)
}

func (c *timeConn) SetReadDeadline(t time.Time) error {
	c.refresh()
	defer c.refresh()
	return c.conn.SetReadDeadline(t)
}

func (c *timeConn) SetWriteDeadline(t time.Time) error {
	c.refresh()
	defer c.refresh()
	return c.conn.SetWriteDeadline(t)
}
