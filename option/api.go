package option

type APIOptions struct {
	Listen          string `json:"listen"`
	Secret          string `json:"secret"`
	Debug           bool   `json:"debug"`
	EnableStatistic bool   `json:"enable-statistic"`
}
