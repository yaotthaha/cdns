package workflow

type RuleMatchPluginOption struct {
	Tag  string         `yaml:"tag"`
	Type string         `yaml:"type"`
	Args map[string]any `yaml:"args"`
}

type RuleExecPluginOption struct {
	Tag  string         `yaml:"tag"`
	Type string         `yaml:"type"`
	Args map[string]any `yaml:"args"`
}
