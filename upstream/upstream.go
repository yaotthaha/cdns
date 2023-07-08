package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option/upstream"

	"github.com/miekg/dns"
)

func NewUpstream(ctx context.Context, logger log.ContextLogger, options upstream.UpstreamOptions) (adapter.Upstream, error) {
	switch options.Type {
	case constant.UpstreamUDP:
		return NewUDPUpstream(ctx, logger, options)
	case constant.UpstreamTCP:
		return NewTCPUpstream(ctx, logger, options)
	case constant.UpstreamTLS:
		return NewTLSUpstream(ctx, logger, options)
	case constant.UpstreamHTTPS:
		return NewHTTPSUpstream(ctx, logger, options)
	case constant.UpstreamQUIC:
		return NewQUICUpstream(ctx, logger, options)
	case constant.UpstreamRandom:
		return NewRandomUpstream(logger, options)
	case constant.UpstreamMulti:
		return NewMultiUpstream(ctx, logger, options)
	case constant.UpstreamQueryTest:
		return NewQueryTestUpstream(ctx, logger, options)
	default:
		return nil, fmt.Errorf("upstream type %s not supported", options.Type)
	}
}

func parseAddress(address string, defaultPort uint16) (string, netip.Addr, uint16, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		if !strings.Contains(err.Error(), "missing port in address") {
			return "", netip.Addr{}, 0, err
		}
		ip, err := netip.ParseAddr(address)
		if err != nil {
			return address, netip.Addr{}, defaultPort, nil
		}
		return "", ip, defaultPort, nil
	}
	if host == "" {
		return "", netip.Addr{}, 0, fmt.Errorf("host is empty")
	}
	portUint, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", netip.Addr{}, 0, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return host, netip.Addr{}, uint16(portUint), err
	}
	return "", ip, uint16(portUint), nil
}

func parseTLSOptions(options upstream.TLSOptions, backupServerName string) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: options.InsecureSkipVerify,
		ServerName:         options.ServerName,
	}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = backupServerName
	}
	if options.ClientCertFile != "" && options.ClientKeyFile == "" {
		return nil, fmt.Errorf("client-key-file not found")
	} else if options.ClientCertFile == "" && options.ClientKeyFile != "" {
		return nil, fmt.Errorf("client-cert-file not found")
	} else if options.ClientCertFile != "" && options.ClientKeyFile != "" {
		keyPair, err := tls.LoadX509KeyPair(options.ClientCertFile, options.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load x509 key pair fail: %s", err)
		}
		tlsConfig.Certificates = []tls.Certificate{keyPair}
	}
	if options.CAFile != nil && len(options.CAFile) > 0 {
		rootCAs := x509.NewCertPool()
		for _, f := range options.CAFile {
			caContent, err := os.ReadFile(f)
			if err != nil {
				return nil, fmt.Errorf("file: %s, load ca fail: %s", f, err)
			}
			if !rootCAs.AppendCertsFromPEM(caContent) {
				return nil, fmt.Errorf("file: %s, append ca fail", f)
			}
		}
		tlsConfig.RootCAs = rootCAs
	}
	return tlsConfig, nil
}

func logDNSMsg(dnsMsg *dns.Msg) string {
	return fmt.Sprintf("qtype: %s, qname: %s", dns.TypeToString[dnsMsg.Question[0].Qtype], dnsMsg.Question[0].Name)
}
