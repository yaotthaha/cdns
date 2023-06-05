package geoip

import (
	"fmt"
	"net"

	"github.com/oschwald/maxminddb-golang"
)

type Reader struct {
	reader *maxminddb.Reader
}

func Open(path string) (*Reader, []string, error) {
	database, err := maxminddb.Open(path)
	if err != nil {
		return nil, nil, err
	}
	if database.Metadata.DatabaseType != "sing-geoip" {
		database.Close()
		return nil, nil, fmt.Errorf("incorrect database type, expected sing-geoip, got %s", database.Metadata.DatabaseType)
	}
	return &Reader{database}, database.Metadata.Languages, nil
}

func (r *Reader) Lookup(ip net.IP) string {
	var code string
	_ = r.reader.Lookup(ip, &code)
	if code != "" {
		return code
	}
	return "unknown"
}
