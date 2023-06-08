package cdns

import (
	"fmt"
	"strings"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/execPlugin"
	"github.com/yaotthaha/cdns/matchPlugin"

	"github.com/spf13/cobra"
)

var versionCommand = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		showVersion()
	},
}

func init() {
	mainCommand.AddCommand(versionCommand)
}

var (
	MatchPlugins []string
	ExecPlugins  []string
)

func GetAllPlugins() string {
	matchPlugin.Register()
	execPlugin.Register()
	MatchPlugins = adapter.GetAllMatchPlugin()
	ExecPlugins = adapter.GetAllExecPlugin()
	str := ""
	mp := MatchPlugins
	if mp != nil && len(mp) > 0 {
		str += "Match Plugins: "
		str += strings.Join(mp, ", ")
	}
	ep := ExecPlugins
	if ep != nil && len(ep) > 0 {
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

func showVersion() {
	fmt.Println(constant.GetVersion())
	fmt.Println("")
	fmt.Println(strings.TrimSpace(GetAllPlugins()))
}
