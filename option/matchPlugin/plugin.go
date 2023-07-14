package matchPlugin

type MatchPluginOptions struct {
	Tag  string         `config:"tag"`
	Type string         `config:"type"`
	Args map[string]any `config:"args"`
}
