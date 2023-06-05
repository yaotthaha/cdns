package execPlugin

import (
	// use custom exec plugin
	_ "github.com/yaotthaha/cdns/execPlugin/cache"
	_ "github.com/yaotthaha/cdns/execPlugin/prefer"
)

func Register() {
}
