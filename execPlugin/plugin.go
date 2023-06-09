package execPlugin

import (
	// use custom exec plugin
	_ "github.com/yaotthaha/cdns/execPlugin/cache"
	_ "github.com/yaotthaha/cdns/execPlugin/ecs"
	_ "github.com/yaotthaha/cdns/execPlugin/host"
	_ "github.com/yaotthaha/cdns/execPlugin/ipset"
	_ "github.com/yaotthaha/cdns/execPlugin/prefer"
	_ "github.com/yaotthaha/cdns/execPlugin/redis-cache"
	_ "github.com/yaotthaha/cdns/execPlugin/workflow-go"
)

func Register() {
}
