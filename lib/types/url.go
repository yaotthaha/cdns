package types

import "net/url"

type URL url.URL

func (u *URL) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	err := unmarshal(&s)
	if err != nil {
		return err
	}
	u2, err := url.Parse(s)
	if err != nil {
		return err
	}
	*u = URL(*u2)
	return nil
}

func (u URL) MarshalYAML() (interface{}, error) {
	u2 := url.URL(u)
	return u2.String(), nil
}
