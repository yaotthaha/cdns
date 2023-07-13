package adapter

type FatalStarter interface {
	WithFatalCloser(func(err error))
}
