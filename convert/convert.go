package convert

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
)

var convertMap = map[string]func(p *clash.Proxies, s *singbox.SingBoxOut) error{
	"vmess":        vmess,
	"vless":        vless,
	"shadowsocks":  ss,
	"shadowsocksr": ss,
	"trojan":       trojan,
	"http":         httpOpts,
	"socks":        socks5,
	"hysteria":     hysteria,
}

func Clash2sing(c clash.Clash) ([]singbox.SingBoxOut, error) {
	sl := make([]singbox.SingBoxOut, 0, len(c.Proxies)+1)
	for _, v := range c.Proxies {
		v := v
		s, t, err := comm(&v)
		if err != nil {
			return nil, fmt.Errorf("clash2sing: %w", err)
		}
		err = convertMap[t](&v, s)
		if err != nil {
			return nil, fmt.Errorf("clash2sing: %w", err)
		}
		sl = append(sl, *s)
	}
	return sl, nil
}

var ErrNotSupportType = errors.New("不支持的类型")

var typeMap = map[string]string{
	"ss":       "shadowsocks",
	"ssr":      "shadowsocksr",
	"vmess":    "vmess",
	"vless":    "vless",
	"trojan":   "trojan",
	"socks5":   "socks5",
	"http":     "http",
	"hysteria": "hysteria",
}

func comm(p *clash.Proxies) (*singbox.SingBoxOut, string, error) {
	s := &singbox.SingBoxOut{}
	s.Type = typeMap[p.Type]
	if s.Type == "" {
		return nil, "", fmt.Errorf("comm: %w", ErrNotSupportType)
	}
	s.Tag = p.Name
	s.Server = p.Server
	port, err := strconv.Atoi(p.Port)
	if err != nil {
		return nil, "", fmt.Errorf("comm: %w", err)
	}
	s.ServerPort = port
	s.Password = p.Password

	return s, s.Type, nil
}
