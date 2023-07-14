package types

import (
	"reflect"

	"github.com/mitchellh/mapstructure"
)

type Listable[T any] []T

func (l *Listable[T]) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var v []T
	err := unmarshal(&v)
	if err == nil {
		*l = v
		return nil
	}
	var singleItem T
	err = unmarshal(&singleItem)
	if err != nil {
		return err
	}
	*l = []T{singleItem}
	return nil
}

func (l Listable[T]) MarshalYAML() (interface{}, error) {
	if len(l) == 1 {
		return l[0], nil
	}
	return ([]T)(l), nil
}

func (l *Listable[T]) Unmarshal(from reflect.Value) error {
	var v []T
	err := mapstructure.Decode(from.Interface(), &v)
	if err == nil {
		*l = v
		return nil
	}
	var singleItem T
	err = mapstructure.Decode(from.Interface(), &singleItem)
	if err != nil {
		return err
	}
	*l = []T{singleItem}
	return nil
}
