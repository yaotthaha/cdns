package listener

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/lib/tools"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/listener"

	"github.com/miekg/dns"
)

type udpListener struct {
	tag      string
	ctx      context.Context
	core     adapter.Core
	logger   log.ContextLogger
	listen   netip.AddrPort
	workflow string
	udpConn  net.PacketConn
}

func NewUDPListener(ctx context.Context, core adapter.Core, logger log.Logger, options listener.ListenerOptions) (adapter.Listener, error) {
	l := &udpListener{
		tag:    options.Tag,
		ctx:    ctx,
		core:   core,
		logger: log.NewContextLogger(log.NewTagLogger(logger, fmt.Sprintf("listener/%s/%s", constant.ListenerUDP, options.Tag))),
	}
	l.listen = options.Listen
	if options.Workflow == "" {
		return nil, fmt.Errorf("workflow is empty")
	}
	l.workflow = options.Workflow
	return l, nil
}

func (l *udpListener) Tag() string {
	return l.tag
}

func (l *udpListener) Type() string {
	return constant.ListenerUDP
}

func (l *udpListener) Start() error {
	w := l.core.GetWorkflow(l.workflow)
	if w == nil {
		return fmt.Errorf("workflow %s not found", l.workflow)
	}
	var err error
	l.udpConn, err = net.ListenPacket(constant.NetworkUDP, l.listen.String())
	if err != nil {
		return fmt.Errorf("listen %s fail: %s", l.listen.String(), err)
	}
	go l.listenHandler()
	return nil
}

func (l *udpListener) Close() error {
	err := l.udpConn.Close()
	if err != nil {
		return fmt.Errorf("listener %s: close udp connection fail: %s", l.tag, err)
	}
	return nil
}

func (l *udpListener) Context() context.Context {
	return l.ctx
}

func (l *udpListener) ContextLogger() log.ContextLogger {
	return l.logger
}

func (l *udpListener) GetWorkflow() adapter.Workflow {
	return l.core.GetWorkflow(l.workflow)
}

func (l *udpListener) listenHandler() {
	for {
		select {
		case <-l.ctx.Done():
			return
		default:
		}
		var buf [dns.MaxMsgSize]byte
		n, remoteAddr, err := l.udpConn.ReadFrom(buf[:])
		if err != nil {
			if tools.IsCloseOrCanceled(err) {
				return
			}
			l.logger.Error(fmt.Sprintf("read fail: %s", err))
			continue
		}
		go l.dialHandler(buf[:n], remoteAddr)
	}
}

func (l *udpListener) dialHandler(buf []byte, remoteAddr net.Addr) {
	select {
	case <-l.ctx.Done():
		return
	default:
	}
	ctx, respBytes := handler(l, buf, remoteAddr)
	if respBytes == nil {
		return
	}
	_, err := l.udpConn.WriteTo(respBytes, remoteAddr)
	if err != nil {
		if tools.IsCloseOrCanceled(err) {
			return
		}
		l.logger.ErrorContext(ctx, fmt.Sprintf("write fail: %s", err))
		return
	}
}
