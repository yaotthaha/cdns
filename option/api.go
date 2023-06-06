package option

type APIOption struct {
	Listen string `json:"listen"`
	Secret string `json:"secret"`
	Debug  bool   `json:"debug"`
}
