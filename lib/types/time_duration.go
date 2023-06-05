package types

import "time"

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
