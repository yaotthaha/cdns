package cdns

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/log"
	option "github.com/yaotthaha/cdns/option/upstream"
	"github.com/yaotthaha/cdns/upstream"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var queryToHexCommand = &cobra.Command{
	Use:   "queryToHex",
	Short: "Query To Hex String",
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(queryToHex())
	},
}

var (
	queryAddress string
	queryDomain  string
	queryType    string
)

func init() {
	mainCommand.AddCommand(queryToHexCommand)
	queryToHexCommand.PersistentFlags().StringVarP(&queryDomain, "domain", "d", "", "domain")
	queryToHexCommand.PersistentFlags().StringVarP(&queryType, "type", "t", "A", "dns query type")
	queryToHexCommand.PersistentFlags().StringVarP(&queryAddress, "address", "a", "223.5.5.5", "dns server address")
}

func queryToHex() int {
	if queryAddress == "" {
		queryAddress = "223.5.5.5"
	}
	if queryDomain == "" {
		fmt.Println("domain is required")
		return 1
	}
	var queryTypeUint16 uint16
	if queryType == "" {
		queryTypeUint16 = dns.TypeA
	} else {
		queryTypeNum, err := strconv.ParseUint(queryType, 10, 16)
		if err == nil {
			queryTypeUint16 = uint16(queryTypeNum)
		} else {
			queryTypeUint16 = dns.StringToType[strings.ToUpper(queryType)]
			if queryTypeUint16 == dns.TypeNone {
				fmt.Println(fmt.Sprintf("invalid type: %s", queryType))
				return 1
			}
		}
	}
	hexStr, err := queryToHexWrapper(queryAddress, queryDomain, queryTypeUint16)
	if err != nil {
		fmt.Println(err)
		return 1
	}
	fmt.Println(fmt.Sprintf("hex string: %s", hexStr))
	return 0
}

func queryToHexWrapper(address string, domain string, typ uint16) (string, error) {
	ctx := context.Background()
	logger := log.NewLogger()
	logger.SetOutput(io.Discard)
	contextLogger := log.NewContextLogger(logger)
	simpleDNSUpstream, err := upstream.NewUDPUpstream(ctx, contextLogger, option.UpstreamOptions{
		Tag:  "simple",
		Type: constant.UpstreamUDP,
		UDPOptions: &option.UpstreamUDPOptions{
			Address: address,
		},
	})
	if err != nil {
		return "", err
	}
	if starter, isStarter := simpleDNSUpstream.(adapter.Starter); isStarter {
		err = starter.Start()
		if err != nil {
			return "", err
		}
	}
	defer func() {
		if closer, isCloser := simpleDNSUpstream.(adapter.Closer); isCloser {
			_ = closer.Close()
		}
	}()
	simpleDNSMsg := new(dns.Msg)
	simpleDNSMsg.SetQuestion(dns.Fqdn(domain), typ)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	respMsg, err := simpleDNSUpstream.Exchange(ctx, simpleDNSMsg)
	if err != nil {
		return "", err
	}
	respMsgPack, err := respMsg.Pack()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(respMsgPack), nil
}
