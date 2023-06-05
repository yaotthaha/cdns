package cdns

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/yaotthaha/cdns/core"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var runCommand = &cobra.Command{
	Use: "run",
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(run())
	},
}

func init() {
	mainCommand.AddCommand(runCommand)
}

func run() int {
	configContent, err := os.ReadFile(paramConfig)
	if err != nil {
		log.DefaultSimpleLogger.Fatal(err)
		return 1
	}
	var options option.Option
	err = yaml.Unmarshal(configContent, &options)
	if err != nil {
		log.DefaultSimpleLogger.Fatal(err)
		return 1
	}
	logger := log.NewLogger()
	if options.LogOption.Disabled {
		logger.SetOutput(io.Discard)
	}
	if options.LogOption.Debug {
		logger.SetDebug(true)
	}
	if options.LogOption.File != "" {
		err := os.Remove(options.LogOption.File)
		if err != nil && !os.IsNotExist(err) {
			log.DefaultSimpleLogger.Fatal(err)
			return 1
		}
		f, err := os.OpenFile(options.LogOption.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			log.DefaultSimpleLogger.Fatal(err)
			return 1
		}
		logger.SetOutput(f)
		defer f.Close()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := core.New(ctx, logger, options)
	if err != nil {
		logger.Fatal(err)
		return 1
	}
	go notifySignal(logger, cancel)
	err = c.Run()
	if err != nil {
		logger.Fatal(err)
		return 1
	}
	return 0
}

func notifySignal(logger log.Logger, cancel context.CancelFunc) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	sig := <-signalChan
	logger.Warn(fmt.Sprintf("receive signal %s, exiting...", sig))
	cancel()
}
