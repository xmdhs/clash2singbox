package clash

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

type wgPeer struct {
	Server       string     `yaml:"server"`
	Port         int        `yaml:"port"`
	IP           string     `yaml:"ip"`
	IPv6         string     `yaml:"ipv6"`
	PublicKey    string     `yaml:"public-key"`
	PreSharedKey string     `yaml:"pre-shared-key"`
	Reserved     wgReserved `yaml:"reserved"`
	AllowedIPs   []string   `yaml:"allowed_ips"`
}

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
