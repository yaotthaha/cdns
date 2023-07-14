package workflow

type RuleMatchPluginOption struct {
	Tag  string         `config:"tag"`
	Type string         `config:"type"`
	Args map[string]any `config:"args"`
}

type RuleExecPluginOption struct {
	Tag  string         `config:"tag"`
	Type string         `config:"type"`
	Args map[string]any `config:"args"`
}
