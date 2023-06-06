package execPlugin

import (
	// use custom exec plugin
	_ "github.com/yaotthaha/cdns/execPlugin/cache"
	_ "github.com/yaotthaha/cdns/execPlugin/prefer"
	_ "github.com/yaotthaha/cdns/execPlugin/workflow-go"
)

func Register() {
}
