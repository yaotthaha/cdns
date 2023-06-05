package matchPlugin

type MatchPluginOption struct {
	Tag  string         `yaml:"tag"`
	Type string         `yaml:"type"`
	Args map[string]any `yaml:"args"`
}
