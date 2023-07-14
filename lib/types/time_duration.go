package types

import (
	"reflect"
	"time"

	"github.com/yaotthaha/cdns/lib/tools"
)

type TimeDuration time.Duration

func (t *TimeDuration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var duration string
	err := unmarshal(&duration)
	if err != nil {
		return err
	}
	d, err := time.ParseDuration(duration)
	if err != nil {
		return err
	}
	*t = TimeDuration(d)
	return nil
}

func (t TimeDuration) MarshalYAML() (interface{}, error) {
	return time.Duration(t).String(), nil
}

func (t *TimeDuration) Unmarshal(from reflect.Value) error {
	var timeStr string
	err := tools.NewMapStructureDecoderWithResult(&timeStr).Decode(from.Interface())
	if err != nil {
		return err
	}
	d, err := time.ParseDuration(timeStr)
	if err != nil {
		return err
	}
	*t = TimeDuration(d)
	return nil
}
