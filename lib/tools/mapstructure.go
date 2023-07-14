package tools

import "github.com/mitchellh/mapstructure"

func NewMapStructureDecoderConfig() *mapstructure.DecoderConfig {
	return &mapstructure.DecoderConfig{
		DecodeHook: mapstructure.UnmarshalInterfaceHookFunc(),
		Squash:     true,
		TagName:    "config",
	}
}

func NewMapStructureDecoderFromConfig(config *mapstructure.DecoderConfig) *mapstructure.Decoder {
	decoder, _ := mapstructure.NewDecoder(config)
	return decoder
}

func NewMapStructureDecoder() *mapstructure.Decoder {
	return NewMapStructureDecoderFromConfig(NewMapStructureDecoderConfig())
}

func NewMapStructureDecoderWithResult(result any) *mapstructure.Decoder {
	decoderConfig := NewMapStructureDecoderConfig()
	decoderConfig.Result = result
	return NewMapStructureDecoderFromConfig(decoderConfig)
}
