package constant

import (
	"fmt"
	"strings"

	"github.com/yaotthaha/cdns/execPlugin"
	"github.com/yaotthaha/cdns/matchPlugin"
)

const Version = "v0.0.1-alpha-3"

var Commit = ""

func GetVersion() string {
	if Commit != "" {
		return fmt.Sprintf("cdns version %s, commit: %s", Version, Commit)
	}
	return fmt.Sprintf("cdns version %s", Version)
}

func GetAllPlugins() string {
	str := ""
	mp := matchPlugin.GetAllMatchPlugin()
	if len(mp) > 0 {
		str += "Match Plugins: "
		str += strings.Join(mp, ", ")
	}
	ep := execPlugin.GetAllExecPlugin()
	if len(ep) > 0 {
		if len(str) > 0 {
			str += "\n"
		}
		str += "Exec Plugins: "
		str += strings.Join(ep, ", ")
	}
	if len(str) > 0 {
		str += "\n"
	}
	if len(str) == 0 {
		str = "No Plugins"
	}
	return str
}
