package cdns

import "github.com/spf13/cobra"

var mainCommand = &cobra.Command{
	Use:   "cdns",
	Short: "A Custom DNS Server",
}

var paramConfig string

func init() {
	mainCommand.PersistentFlags().StringVarP(&paramConfig, "config", "c", "config.yaml", "config file")
}

func Run() error {
	return mainCommand.Execute()
}
