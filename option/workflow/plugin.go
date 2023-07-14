package workflow

type RuleMatchPluginOption struct {
	Tag  string         `config:"tag"`
	Args map[string]any `config:"args"`
}

type RuleExecPluginOption struct {
	Tag  string         `config:"tag"`
	Args map[string]any `config:"args"`
}
