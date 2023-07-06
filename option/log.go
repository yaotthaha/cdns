package option

type LogOptions struct {
	Disabled          bool   `yaml:"disabled,omitempty"`
	File              string `yaml:"file,omitempty"`
	Debug             bool   `yaml:"debug,omitempty"`
	DisableTimestamp  bool   `yaml:"disable-timestamp,omitempty"`
	EnableColorOutput bool   `yaml:"enable-color-output,omitempty"`
}
