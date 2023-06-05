package option

type LogOption struct {
	Disabled bool   `yaml:"disabled,omitempty"`
	File     string `yaml:"file,omitempty"`
	Debug    bool   `yaml:"debug,omitempty"`
}
