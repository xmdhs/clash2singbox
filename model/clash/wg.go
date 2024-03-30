package clash

type wgPeer struct {
	Server       string      `yaml:"server"`
	Port         MyInt       `yaml:"port"`
	IP           string      `yaml:"ip"`
	IPv6         string      `yaml:"ipv6"`
	PublicKey    string      `yaml:"public-key"`
	PreSharedKey string      `yaml:"pre-shared-key"`
	Reserved     *wgReserved `yaml:"reserved"`
	AllowedIPs   []string    `yaml:"allowed_ips"`
}
