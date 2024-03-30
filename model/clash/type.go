package clash

import (
	"fmt"
	"strconv"

	"gopkg.in/yaml.v3"
)

type wgReserved struct {
	Value []uint8
}

func (w *wgReserved) UnmarshalYAML(v *yaml.Node) error {
	var s string
	err := v.Decode(&s)
	if err == nil {
		w.Value = []byte(s)
		return nil
	}
	err = v.Decode(&w.Value)
	if err != nil {
		return fmt.Errorf("wgReserved.UnmarshalYAML: %w", err)
	}
	return nil
}

type MyBool bool

func (b *MyBool) UnmarshalYAML(v *yaml.Node) error {
	var Bool bool
	err := v.Decode(&Bool)
	if err == nil {
		*b = MyBool(Bool)
		return nil
	}
	var i int
	err = v.Decode(&i)
	if err != nil {
		return fmt.Errorf("MyBool.UnmarshalYAML: %w", err)
	}
	if i == 1 {
		*b = true
	}
	return nil
}

type MyInt int

func (i *MyInt) UnmarshalYAML(v *yaml.Node) error {
	var num int
	err := v.Decode(&num)
	if err == nil {
		*i = MyInt(num)
		return nil
	}
	var str string
	err = v.Decode(&str)
	if err != nil {
		return fmt.Errorf("MyInt.UnmarshalYAML: %w", err)
	}
	num, err = strconv.Atoi(str)
	if err != nil {
		return fmt.Errorf("MyInt.UnmarshalYAML: %w", err)
	}
	*i = MyInt(num)
	return nil
}
