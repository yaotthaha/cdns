package option

type LogOptions struct {
	Disabled          bool   `config:"disabled,omitempty"`
	File              string `config:"file,omitempty"`
	Debug             bool   `config:"debug,omitempty"`
	DisableTimestamp  bool   `config:"disable-timestamp,omitempty"`
	EnableColorOutput bool   `config:"enable-color-output,omitempty"`
}
