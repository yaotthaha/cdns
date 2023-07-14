package types

import (
	"reflect"
	"time"

	"github.com/mitchellh/mapstructure"
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
	err := mapstructure.Decode(from.Interface(), &timeStr)
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
