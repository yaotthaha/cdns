package adapter

type FatalStarter interface {
	WithFatalCloser(func(error))
}
