package adapter

type Core interface {
	Run() error
	GetUpstream(string) Upstream
	GetWorkflow(string) Workflow
	GetMatchPlugin(string) MatchPlugin
	GetExecPlugin(string) ExecPlugin
}
