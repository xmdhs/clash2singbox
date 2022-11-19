package main

import (
	"encoding/json"
	"os"

	"github.com/xmdhs/clash2singbox/clash"
	"github.com/xmdhs/clash2singbox/convert"
	"gopkg.in/yaml.v3"
)

func main() {
	b, err := os.ReadFile("1.yaml")
	if err != nil {
		panic(err)
	}
	c := clash.Clash{}
	err = yaml.Unmarshal(b, &c)
	if err != nil {
		panic(err)
	}
	s, err := convert.Clash2sing(c)
	if err != nil {
		panic(err)
	}
	bb, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile("1.json", bb, 0777)
	if err != nil {
		panic(err)
	}
}
