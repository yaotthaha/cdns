package adapter

type Core interface {
	Run() error
	GetUpstream(string) Upstream
	ListUpstream() []Upstream
	GetWorkflow(string) Workflow
	GetMatchPlugin(string) MatchPlugin
	GetExecPlugin(string) ExecPlugin
}

type WithCore interface {
	WithCore(Core)
}
