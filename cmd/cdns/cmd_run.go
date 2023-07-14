package cdns

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/yaotthaha/cdns/adapter"
	"github.com/yaotthaha/cdns/constant"
	"github.com/yaotthaha/cdns/core"
	"github.com/yaotthaha/cdns/log"
	"github.com/yaotthaha/cdns/option"

	"github.com/spf13/cobra"
)

var runCommand = &cobra.Command{
	Use:   "run",
	Short: "Run Server",
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(run())
	},
}

func init() {
	mainCommand.AddCommand(runCommand)
}

type Core struct {
	options       *option.Options
	core          adapter.Core
	logger        *log.SimpleLogger
	ctx           context.Context
	cancel        context.CancelFunc
	logFileCloser adapter.Closer
	closeCtx      context.Context
	closeFn       context.CancelFunc
}

func newCore(options *option.Options) (*Core, error) {
	logger := log.NewLogger()
	if options.LogOptions.Disabled {
		logger.SetOutput(io.Discard)
	}
	if options.LogOptions.Debug {
		logger.SetDebug(true)
	}
	if options.LogOptions.DisableTimestamp {
		logger.SetFormatFunc(log.DisableTimestampFormatFunc)
	}
	if options.LogOptions.EnableColorOutput {
		logger.SetColor(true)
	}
	cr := &Core{
		options: options,
		logger:  logger,
	}
	if options.LogOptions.File != "" {
		err := os.Remove(options.LogOptions.File)
		if err != nil && !os.IsNotExist(err) {
			log.DefaultSimpleLogger.Fatal(err)
			return nil, err
		}
		f, err := os.OpenFile(options.LogOptions.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			log.DefaultSimpleLogger.Fatal(err)
			return nil, err
		}
		logger.SetOutput(f)
		cr.logFileCloser = f
	}
	ctx, cancel := context.WithCancel(context.Background())
	c, err := core.New(ctx, logger, *options)
	if err != nil {
		logger.Fatal(err)
		cancel()
		return nil, err
	}
	cr.ctx = ctx
	cr.cancel = cancel
	cr.core = c
	cr.closeCtx, cr.closeFn = context.WithCancel(context.Background())
	return cr, nil
}

func (c *Core) Start() error {
	go func() {
		err := c.core.Run()
		if err != nil {
			c.logger.Fatal(err)
		}
		c.cancel()
		c.closeFn()
	}()
	return nil
}

func (c *Core) Close() error {
	c.cancel()
	<-c.closeCtx.Done()
	if c.logFileCloser != nil {
		c.logFileCloser.Close()
	}
	return nil
}

func run() int {
	var options *option.Options
	var err error
	options, err = option.ReadFile(paramConfig)
	if err != nil {
		log.DefaultSimpleLogger.Fatal(err)
		return 1
	}
	c, err := newCore(options)
	if err != nil {
		log.DefaultSimpleLogger.Fatal(err)
		return 1
	}
	c.logger.Info(constant.GetVersion())
	err = c.Start()
	if err != nil {
		log.DefaultSimpleLogger.Fatal(err)
		return 1
	}
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for {
		select {
		case <-c.closeCtx.Done():
			return 1
		case sig := <-signalChan:
			switch sig {
			case syscall.SIGHUP:
				c.logger.Info("reload config...")
				_options, err := option.ReadFile(paramConfig)
				if err != nil {
					c.logger.Fatal(fmt.Sprintf("reload config failed: %s", err))
					continue
				}
				nc, err := newCore(_options)
				if err != nil {
					c.logger.Fatal(fmt.Sprintf("reload config failed: %s", err))
					continue
				}
				c.Close()
				err = nc.Start()
				if err != nil {
					log.DefaultSimpleLogger.Warn(fmt.Sprintf("reload config failed: %s, use old options", err))
					nc, err := newCore(options)
					if err != nil {
						log.DefaultSimpleLogger.Fatal(fmt.Sprintf("use old options failed: %s", err))
						return 1
					}
					err = nc.Start()
					if err != nil {
						log.DefaultSimpleLogger.Fatal(fmt.Sprintf("use old options failed: %s", err))
						return 1
					}
				}
				c = nc
				options = _options
			default:
				c.logger.Warn(fmt.Sprintf("receive signal %s, exiting...", sig))
				c.Close()
				return 1
			}
		}
	}
}

func notifySignal(logger log.Logger, cancel context.CancelFunc) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	sig := <-signalChan
	logger.Warn(fmt.Sprintf("receive signal %s, exiting...", sig))
	cancel()
}
