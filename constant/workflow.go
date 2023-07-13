package constant

type ReturnMode string

const (
	ReturnOnce ReturnMode = "return-once"
	ReturnAll  ReturnMode = "return-all"
	Continue   ReturnMode = "no-return"
)
