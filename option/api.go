package option

type APIOptions struct {
	Listen          string `yaml:"listen,omitempty"`
	Secret          string `yaml:"secret,omitempty"`
	Debug           bool   `yaml:"debug,omitempty"`
	EnableStatistic bool   `yaml:"enable-statistic,omitempty"`
}
