package execPlugin

import (
	"github.com/yaotthaha/cdns/adapter"
	// use custom exec plugin
	_ "github.com/yaotthaha/cdns/execPlugin/cache"
	_ "github.com/yaotthaha/cdns/execPlugin/prefer"
	// _ "github.com/yaotthaha/cdns/execPlugin/redis-cache"
	_ "github.com/yaotthaha/cdns/execPlugin/workflow-go"
)

func Register() {
}

func GetAllExecPlugin() []string {
	return adapter.GetAllExecPlugin()
}
