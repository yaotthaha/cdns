package listener

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/lib/tools"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/listener"
)

type tcpListener struct {
	tag         string
	ctx         context.Context
	core        adapter.Core
	logger      log.ContextLogger
	listen      netip.AddrPort
	workflow    string
	tcpListener net.Listener
}

func NewTCPListener(ctx context.Context, core adapter.Core, logger log.Logger, options listener.ListenerOptions) (adapter.Listener, error) {
	l := &tcpListener{
		tag:    options.Tag,
		ctx:    ctx,
		core:   core,
		logger: log.NewContextLogger(log.NewTagLogger(logger, fmt.Sprintf("listener/%s/%s", constant.ListenerTCP, options.Tag))),
	}
	l.listen = options.Listen
	if options.Workflow == "" {
		return nil, fmt.Errorf("workflow is empty")
	}
	l.workflow = options.Workflow
	return l, nil
}

func (l *tcpListener) Tag() string {
	return l.tag
}

func (l *tcpListener) Type() string {
	return constant.ListenerTCP
}

func (l *tcpListener) Start() error {
	w := l.core.GetWorkflow(l.workflow)
	if w == nil {
		return fmt.Errorf("workflow %s not found", l.workflow)
	}
	var err error
	listenConfig := &net.ListenConfig{}
	l.tcpListener, err = listenConfig.Listen(l.ctx, constant.NetworkTCP, l.listen.String())
	if err != nil {
		return fmt.Errorf("listen %s fail: %s", l.listen.String(), err)
	}
	go l.listenHandler()
	return nil
}

func (l *tcpListener) Close() error {
	err := l.tcpListener.Close()
	if err != nil {
		return fmt.Errorf("listener %s: close tcp listener fail: %s", l.tag, err)
	}
	return nil
}

func (l *tcpListener) Context() context.Context {
	return l.ctx
}

func (l *tcpListener) ContextLogger() log.ContextLogger {
	return l.logger
}

func (l *tcpListener) GetWorkflow() adapter.Workflow {
	return l.core.GetWorkflow(l.workflow)
}

func (l *tcpListener) listenHandler() {
	for {
		select {
		case <-l.ctx.Done():
			return
		default:
		}
		conn, err := l.tcpListener.Accept()
		if err != nil {
			if err == net.ErrClosed || strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			l.logger.Error(fmt.Sprintf("accept connection fail: %s", err))
			continue
		}
		go l.dialHandler(conn)
	}
}

func (l *tcpListener) dialHandler(conn net.Conn) {
	defer conn.Close()
	for {
		select {
		case <-l.ctx.Done():
			return
		default:
		}
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		lengthBytes := make([]byte, 2)
		_, err := conn.Read(lengthBytes)
		if err != nil {
			if tools.IsCloseOrCanceled(err) {
				return
			}
			l.logger.Error(fmt.Sprintf("read 2-bytes from connection fail: %s", err))
			continue
		}
		buf := make([]byte, int(lengthBytes[0])<<8+int(lengthBytes[1]))
		n, err := conn.Read(buf)
		if err != nil {
			if tools.IsCloseOrCanceled(err) {
				return
			}
			l.logger.Error(fmt.Sprintf("read from connection fail: %s", err))
			continue
		}
		ctx, respBytes := handler(l, buf[:n], conn.RemoteAddr())
		if respBytes == nil {
			continue
		}
		lengthBytes = make([]byte, 2)
		lengthBytes[0] = byte(len(respBytes) >> 8)
		lengthBytes[1] = byte(len(respBytes))
		tcpPayload := append(lengthBytes, respBytes...)
		_, err = conn.Write(tcpPayload)
		if err != nil {
			if tools.IsCloseOrCanceled(err) {
				return
			}
			l.logger.ErrorContext(ctx, fmt.Sprintf("write to connection fail: %s", err))
			continue
		}
	}
}
