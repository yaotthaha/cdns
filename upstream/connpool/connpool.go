package connpool

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type ConnPool struct {
	create        func() (net.Conn, error)
	preCloseCall  func(net.Conn)
	postCloseCall func(net.Conn)
	res           chan *timeConn
	isClosed      atomic.Bool
	maxConn       uint
	idleTimeout   time.Duration
	lock          sync.Mutex
}

func New(maxConn uint, idleTimeout time.Duration, create func() (net.Conn, error)) *ConnPool {
	p := &ConnPool{
		create:      create,
		res:         make(chan *timeConn, maxConn),
		maxConn:     maxConn,
		idleTimeout: idleTimeout,
	}
	go p.check()
	return p
}

func (p *ConnPool) SetPreCloseCall(f func(net.Conn)) {
	p.preCloseCall = f
}

func (p *ConnPool) SetPostCloseCall(f func(net.Conn)) {
	p.postCloseCall = f
}

func (p *ConnPool) check() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if p.isClosed.Load() {
			return
		}
		n := len(p.res)
		for {
			if n == 0 {
				break
			}
			select {
			case conn := <-p.res:
				if p.isClosed.Load() {
					return
				}
				if time.Now().Sub(conn.lastActive) > p.idleTimeout {
					if p.preCloseCall != nil {
						go p.preCloseCall(conn.conn)
					}
					conn.conn.Close()
					if p.postCloseCall != nil {
						go p.postCloseCall(conn.conn)
					}
					n--
					continue
				}
				select {
				case p.res <- conn:
					n--
					continue
				default:
				}
			default:
			}
			break
		}
		if p.isClosed.Load() {
			return
		}
		<-ticker.C
	}
}

func (p *ConnPool) Get() (net.Conn, error) {
	if p.isClosed.Load() {
		return nil, net.ErrClosed
	}
	for {
		select {
		case conn, ok := <-p.res:
			if ok {
				return conn, nil
			}
		default:
		}
		break
	}
	if p.isClosed.Load() {
		return nil, net.ErrClosed
	}
	conn, err := p.create()
	if err != nil {
		return nil, err
	}
	if p.isClosed.Load() {
		return nil, net.ErrClosed
	}
	tConn := newTimeConn(conn)
	return tConn, nil
}

func (p *ConnPool) Put(conn net.Conn) error {
	if p.isClosed.Load() {
		return net.ErrClosed
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	var tConn *timeConn
	if _, ok := conn.(*timeConn); !ok {
		tConn = newTimeConn(conn)
	} else {
		tConn = conn.(*timeConn)
	}
	select {
	case p.res <- tConn:
	default:
		if p.preCloseCall != nil {
			go p.preCloseCall(tConn.conn)
		}
		tConn.conn.Close()
		if p.postCloseCall != nil {
			go p.postCloseCall(tConn.conn)
		}
	}
	return nil
}

func (p *ConnPool) Close() {
	if p.isClosed.Load() {
		return
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	p.isClosed.Store(true)
	for {
		select {
		case conn := <-p.res:
			if p.preCloseCall != nil {
				go p.preCloseCall(conn.conn)
			}
			conn.conn.Close()
			if p.postCloseCall != nil {
				go p.postCloseCall(conn.conn)
			}
			continue
		default:
		}
		break
	}
	close(p.res)
}
