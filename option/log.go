package option

type LogOptions struct {
	Disabled         bool   `yaml:"disabled,omitempty"`
	File             string `yaml:"file,omitempty"`
	Debug            bool   `yaml:"debug,omitempty"`
	DisableTimestamp bool   `yaml:"disable_timestamp,omitempty"`
}
