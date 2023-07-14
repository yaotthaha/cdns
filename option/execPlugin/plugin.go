package execPlugin

type ExecPluginOptions struct {
	Tag  string         `config:"tag"`
	Type string         `config:"type"`
	Args map[string]any `config:"args"`
}
