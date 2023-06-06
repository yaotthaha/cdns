package cdns

import (
	"fmt"

	"github.com/yaotthaha/cdns/constant"

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

func showVersion() {
	fmt.Println(constant.GetVersion())
}
