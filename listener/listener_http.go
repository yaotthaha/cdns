package listener

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/lib/tools"
	"github.com/yaotthaha/cdns/lib/types"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/listener"

	"github.com/go-chi/chi"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

var _ adapter.Listener = (*httpListener)(nil)

type httpListener struct {
	tag              string
	ctx              context.Context
	core             adapter.Core
	logger           log.ContextLogger
	fatalStartCloser func(error)
	listen           netip.AddrPort
	workflow         string
	path             string
	realIPHeader     []string
	trustIP          []any
	tlsConfig        *tls.Config
	useH3            bool
	quicConfig       *quic.Config
	chiRouter        chi.Router
	httpServer       *http.Server
	httpListener     net.Listener
	http3Server      *http3.Server
	udpConn          net.PacketConn
	dnsMsgPool       types.SyncPool[*dns.Msg]
}

func NewHTTPListener(ctx context.Context, core adapter.Core, logger log.ContextLogger, options listener.ListenerOptions) (adapter.Listener, error) {
	l := &httpListener{
		tag:    options.Tag,
		ctx:    ctx,
		core:   core,
		logger: logger,
	}
	l.dnsMsgPool.New(func() *dns.Msg {
		return new(dns.Msg)
	})
	if options.Options == nil {
		return nil, fmt.Errorf("listener options is required")
	}
	httpOptions := options.Options.(*listener.ListenHTTPOptions)
	if httpOptions.Path != "" {
		l.path = httpOptions.Path
	} else {
		l.path = "/dns-query"
	}
	if !httpOptions.EnableH3 {
		if httpOptions.TLSOptions != nil {
			tlsConfig := &tls.Config{}
			err := parseTLSOptions(tlsConfig, *httpOptions.TLSOptions)
			if err != nil {
				return nil, fmt.Errorf("create http listener fail: %s", err)
			}
			l.tlsConfig = tlsConfig
			l.tlsConfig.NextProtos = []string{http2.NextProtoTLS, "http/1.1"}
			listenAddr, err := parseBasicOptions(httpOptions.Listen, 443)
			if err != nil {
				return nil, fmt.Errorf("create http listener fail: %s", err)
			}
			l.listen = listenAddr
		} else {
			listenAddr, err := parseBasicOptions(httpOptions.Listen, 80)
			if err != nil {
				return nil, fmt.Errorf("create http listener fail: %s", err)
			}
			l.listen = listenAddr
		}
	} else {
		listenAddr, err := parseBasicOptions(httpOptions.Listen, 80)
		if err != nil {
			return nil, fmt.Errorf("create http listener fail: %s", err)
		}
		l.listen = listenAddr
		if httpOptions.TLSOptions == nil {
			return nil, fmt.Errorf("create http listener fail: tls options is required when use protocol 3")
		}
		tlsConfig := http3.ConfigureTLSConfig(&tls.Config{})
		err = parseTLSOptions(tlsConfig, *httpOptions.TLSOptions)
		if err != nil {
			return nil, fmt.Errorf("create http listener fail: %s", err)
		}
		l.tlsConfig = tlsConfig
		l.tlsConfig.NextProtos = []string{"h3"}
		l.quicConfig = &quic.Config{
			MaxIdleTimeout:        5 * time.Minute,
			MaxIncomingStreams:    math.MaxUint16,
			MaxIncomingUniStreams: math.MaxUint16,
			Allow0RTT:             true,
		}
	}
	if httpOptions.ReadIPHeader != nil && len(httpOptions.ReadIPHeader) > 0 {
		l.realIPHeader = httpOptions.ReadIPHeader
	}
	if httpOptions.TrustIP != nil && len(httpOptions.TrustIP) > 0 {
		ips := make([]any, 0)
		for _, addr := range httpOptions.TrustIP {
			ip, err := netip.ParseAddr(addr)
			if err == nil {
				ips = append(ips, ip)
				continue
			}
			cidr, err := netip.ParsePrefix(addr)
			if err == nil {
				ips = append(ips, cidr)
				continue
			}
			return nil, fmt.Errorf("create http listener fail: invalid trust-ip: %s", addr)
		}
		l.trustIP = ips
	}
	if options.Workflow == "" {
		return nil, fmt.Errorf("create http listener fail: workflow is empty")
	}
	l.workflow = options.Workflow
	return l, nil
}

func (l *httpListener) Tag() string {
	return l.tag
}

func (l *httpListener) Type() string {
	return constant.ListenerHTTP
}

func (l *httpListener) Start() error {
	w := l.core.GetWorkflow(l.workflow)
	if w == nil {
		return fmt.Errorf("start http listener fail: workflow %s not found", l.workflow)
	}
	chiRouter := chi.NewRouter()
	chiRouter.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintln(w, []byte("404"))
	})
	chiRouter.Get(l.path, l.httpHandler)
	chiRouter.Post(l.path, l.httpHandler)
	l.chiRouter = chiRouter
	if !l.useH3 {
		httpServer := &http.Server{
			Addr:              l.listen.String(),
			Handler:           l.chiRouter,
			ReadHeaderTimeout: 10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       1 * time.Minute,
			MaxHeaderBytes:    512,
		}
		l.httpServer = httpServer
		if l.tlsConfig != nil {
			httpServer.TLSConfig = l.tlsConfig
			err := http2.ConfigureServer(httpServer, &http2.Server{
				MaxReadFrameSize:             16 * 1024,
				IdleTimeout:                  30 * time.Second,
				MaxUploadBufferPerConnection: 65535,
				MaxUploadBufferPerStream:     65535,
			})
			if err != nil {
				return fmt.Errorf("start http listener fail: %s", err)
			}
			tcpListener, err := net.Listen(constant.NetworkTCP, l.listen.String())
			if err != nil {
				return fmt.Errorf("start http listener fail: %s", err)
			}
			tlsListener := tls.NewListener(tcpListener, l.tlsConfig)
			l.httpListener = tlsListener
		} else {
			tcpListener, err := net.Listen(constant.NetworkTCP, l.listen.String())
			if err != nil {
				return fmt.Errorf("start http listener fail: %s", err)
			}
			l.httpListener = tcpListener
		}
		go func() {
			l.logger.Info(fmt.Sprintf("start http listener on %s", l.listen.String()))
			err := l.httpServer.Serve(l.httpListener)
			if err != nil {
				if tools.IsCloseOrCanceled(err) {
					return
				}
				if l.fatalStartCloser != nil {
					l.fatalStartCloser(fmt.Errorf("start http listener fail: %s", err))
				}
				l.logger.Fatal(fmt.Sprintf("start http listener fail: %s", err))
			}
		}()
	} else {
		http3Server := &http3.Server{
			Addr:       l.listen.String(),
			Port:       int(l.listen.Port()),
			TLSConfig:  l.tlsConfig,
			QuicConfig: l.quicConfig,
			Handler:    l.chiRouter,
		}
		l.http3Server = http3Server
		var err error
		l.udpConn, err = net.ListenUDP(constant.NetworkUDP, &net.UDPAddr{
			IP:   l.listen.Addr().AsSlice(),
			Port: int(l.listen.Port()),
		})
		if err != nil {
			return fmt.Errorf("start http listener fail: %s", err)
		}
		go func() {
			l.logger.Info(fmt.Sprintf("start http listener on %s", l.listen.String()))
			err := l.http3Server.Serve(l.udpConn)
			if err != nil {
				if tools.IsCloseOrCanceled(err) {
					return
				}
				if l.fatalStartCloser != nil {
					l.fatalStartCloser(fmt.Errorf("start http listener fail: %s", err))
				}
				l.logger.Fatal(fmt.Sprintf("start http listener fail: %s", err))
			}
		}()
	}
	return nil
}

func (l *httpListener) Close() error {
	var err error
	if !l.useH3 {
		err = l.httpServer.Close()
		if err != nil {
			err = fmt.Errorf("close http listener fail: %s", err)
			l.httpListener.Close()
		} else {
			err = l.httpListener.Close()
			if err != nil {
				err = fmt.Errorf("close http listener fail: %s", err)
			}
		}
	} else {
		err = l.http3Server.Close()
		if err != nil {
			err = fmt.Errorf("close http listener fail: %s", err)
			l.udpConn.Close()
		} else {
			err = l.udpConn.Close()
			if err != nil {
				err = fmt.Errorf("close http listener fail: %s", err)
			}
		}
	}
	return err
}

func (l *httpListener) WithFatalCloser(f func(err error)) {
	l.fatalStartCloser = f
}

func (l *httpListener) Context() context.Context {
	return l.ctx
}

func (l *httpListener) ContextLogger() log.ContextLogger {
	return l.logger
}

func (l *httpListener) GetWorkflow() adapter.Workflow {
	return l.core.GetWorkflow(l.workflow)
}

func (l *httpListener) parseNetAddr(addr string) *netAddr {
	var network string
	if l.useH3 {
		network = constant.NetworkUDP
	} else {
		network = constant.NetworkTCP
	}
	return &netAddr{
		network: network,
		addr:    addr,
	}
}

func (l *httpListener) httpHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	remoteAddrPort, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return
	}
	var remoteIP netip.Addr
	if l.realIPHeader != nil {
		if l.trustIP != nil {
			trust := false
			for _, tAddr := range l.trustIP {
				switch addr := tAddr.(type) {
				case netip.Addr:
					if addr.Compare(remoteAddrPort.Addr()) == 0 {
						trust = true
						break
					}
					continue
				case netip.Prefix:
					if addr.Contains(remoteAddrPort.Addr()) {
						trust = true
						break
					}
					continue
				}
				break
			}
			if trust {
				for _, rh := range l.realIPHeader {
					ipStr := r.Header.Get(rh)
					if len(ipStr) > 0 {
						ip, err := netip.ParseAddr(ipStr)
						if err != nil {
							return
						}
						remoteIP = ip
						break
					}
				}
			} else {
				remoteIP = remoteAddrPort.Addr()
			}
		} else {
			for _, rh := range l.realIPHeader {
				ipStr := r.Header.Get(rh)
				if len(ipStr) > 0 {
					ip, err := netip.ParseAddr(ipStr)
					if err != nil {
						return
					}
					remoteIP = ip
					break
				}
			}
		}
	} else {
		remoteIP = remoteAddrPort.Addr()
	}
	for k := range r.Header {
		switch k {
		case "Content-Type":
			if r.Header.Get(k) != "application/dns-message" {
				l.logger.Debug(fmt.Sprintf("http request header Content-Type is not application/dns-message"))
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintln(w, []byte("400 Bad Request"))
				return
			}
		}
	}
	var rawDNSMsg []byte
	// from mosdns(https://github.com/IrineSistiana/mosdns), thank for @IrineSistiana
	switch r.Method {
	case http.MethodGet:
		s := r.URL.Query().Get("dns")
		if len(s) == 0 {
			l.logger.Debug(fmt.Sprintf("http request query dns is empty"))
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, []byte("400 Bad Request"))
			return
		}
		msgSize := base64.RawURLEncoding.DecodedLen(len(s))
		if msgSize > dns.MaxMsgSize {
			l.logger.Debug(fmt.Sprintf("msg length %d is too big", msgSize))
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, []byte("400 Bad Request"))
			return
		}
		rawDNSMsg, err = base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			l.logger.Debug(fmt.Sprintf("failed to decode base64 query: %s", err))
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, []byte("400 Bad Request"))
			return
		}
	case http.MethodPost:
		buf := bytes.NewBuffer(nil)
		_, err = buf.ReadFrom(io.LimitReader(r.Body, dns.MaxMsgSize))
		if err != nil {
			l.logger.Debug(fmt.Sprintf("failed to read request body: %w", err))
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, []byte("400 Bad Request"))
			return
		}
		rawDNSMsg = buf.Bytes()
	}
	dnsMsg := l.dnsMsgPool.Get()
	defer func() {
		cleanDNSMsg(dnsMsg)
		l.dnsMsgPool.Put(dnsMsg)
	}()
	err = dnsMsg.Unpack(rawDNSMsg)
	if err != nil {
		l.logger.Debug(fmt.Sprintf("read http request body fail: %s", err))
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, []byte("400 Bad Request"))
		return
	}
	ctx, respMsg := handler(l.core, l, dnsMsg, remoteIP)
	if respMsg == nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, []byte("500 Server Internal Error"))
		return
	}
	respMsgBytes, err := respMsg.Pack()
	if err != nil {
		l.logger.DebugContext(ctx, fmt.Sprintf("pack dns message fail: %s", err))
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, []byte("500 Server Internal Error"))
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	w.Write(respMsgBytes)
}

func cleanDNSMsg(dnsMsg *dns.Msg) {
	dnsMsg.MsgHdr = dns.MsgHdr{}
	dnsMsg.Compress = false
	dnsMsg.Question = nil
	dnsMsg.Answer = nil
	dnsMsg.Ns = nil
	dnsMsg.Extra = nil
}

type netAddr struct {
	network string
	addr    string
}

func (n *netAddr) Network() string {
	return n.network
}

func (n *netAddr) String() string {
	return n.addr
}
