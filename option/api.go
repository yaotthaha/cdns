package option

type APIOptions struct {
	Listen          string `config:"listen,omitempty"`
	Secret          string `config:"secret,omitempty"`
	Debug           bool   `config:"debug,omitempty"`
	EnableStatistic bool   `config:"enable-statistic,omitempty"`
}
