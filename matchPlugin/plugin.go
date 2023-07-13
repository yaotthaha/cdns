package matchPlugin

import (
	// use custom match plugin
	_ "github.com/yaotthaha/cdns/matchPlugin/domain"
	_ "github.com/yaotthaha/cdns/matchPlugin/ip"

	// _ "github.com/yaotthaha/cdns/matchPlugin/script"
	_ "github.com/yaotthaha/cdns/matchPlugin/sing-geoip"
	_ "github.com/yaotthaha/cdns/matchPlugin/sing-geosite"
)

func Register() {
}
