package execPlugin

import (
	// use custom exec plugin
	_ "github.com/yaotthaha/cdns/execPlugin/cache"
	_ "github.com/yaotthaha/cdns/execPlugin/concurrent-workflow"
	// _ "github.com/yaotthaha/cdns/execPlugin/custom-result"
	_ "github.com/yaotthaha/cdns/execPlugin/ecs"
	_ "github.com/yaotthaha/cdns/execPlugin/hosts"
	_ "github.com/yaotthaha/cdns/execPlugin/ipset"
	_ "github.com/yaotthaha/cdns/execPlugin/nftset"
	_ "github.com/yaotthaha/cdns/execPlugin/prefer"
	_ "github.com/yaotthaha/cdns/execPlugin/redis-cache"
)

func Register() {
}
