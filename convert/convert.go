package convert

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
)

func Clash2sing(c clash.Clash) ([]singbox.SingBoxOut, error) {
	sl := make([]singbox.SingBoxOut, 0, len(c.Proxies)+1)
	for _, v := range c.Proxies {
		v := v
		s, t, err := comm(&v)
		if err != nil {
			return nil, fmt.Errorf("clash2sing: %w", err)
		}
		switch t {
		case "vmess":
			err = vmess(&v, s)
		case "shadowsocks":
			err = ss(&v, s)
		case "trojan":
			err = trojan(&v, s)
		case "http":
			err = httpOpts(&v, s)
		case "socks":
			err = socks5(&v, s)
		}
		if err != nil {
			return nil, fmt.Errorf("clash2sing: %w", err)
		}
		sl = append(sl, *s)
	}
	return sl, nil
}

var ErrNotSupportType = errors.New("不支持的类型")

func comm(p *clash.Proxies) (*singbox.SingBoxOut, string, error) {
	s := &singbox.SingBoxOut{}
	switch p.Type {
	case "ss":
		s.Type = "shadowsocks"
	case "vmess":
		s.Type = "vmess"
	case "trojan":
		s.Type = "trojan"
	case "socks5":
		s.Type = "socks"
	case "http":
		s.Type = "http"
	default:
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
