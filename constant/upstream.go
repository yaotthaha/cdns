package constant

import "time"

const (
	UpstreamTCP   = "tcp"
	UpstreamUDP   = "udp"
	UpstreamTLS   = "tls"
	UpstreamHTTPS = "https"
	UpstreamQUIC  = "quic"
)

const (
	UpstreamRandom = "random"
	UpstreamMulti  = "multi"
)

const (
	NetworkTCP = "tcp"
	NetworkUDP = "udp"
)

const (
	TCPDialTimeout = 20 * time.Second
	UDPDialTimeout = 20 * time.Second
	TCPIdleTimeout = 2 * time.Minute
	UDPIdleTimeout = 5 * time.Minute
)

const DNSQueryTimeout = 10 * time.Second

const MaxConn = 16

const (
	ListenerUDP  = "udp"
	ListenerTCP  = "tcp"
	ListenerTLS  = "tls"
	ListenerHTTP = "http"
)
