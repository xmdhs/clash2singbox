package convert

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
)

var convertMap = map[string]func(*clash.Proxies, *singbox.SingBoxOut) ([]singbox.SingBoxOut, error){
	"vmess":        warpOldConver(vmess),
	"vless":        warpOldConver(vless),
	"shadowsocks":  ss,
	"shadowsocksr": ss,
	"trojan":       warpOldConver(trojan),
	"http":         warpOldConver(httpOpts),
	"socks":        warpOldConver(socks5),
	"hysteria":     warpOldConver(hysteria),
	"wireguard":    wireguard,
}

func warpOldConver(f func(*clash.Proxies, *singbox.SingBoxOut) error) func(*clash.Proxies, *singbox.SingBoxOut) ([]singbox.SingBoxOut, error) {
	return func(c *clash.Proxies, p *singbox.SingBoxOut) ([]singbox.SingBoxOut, error) {
		err := f(c, p)
		return []singbox.SingBoxOut{*p}, err
	}
}

func Clash2sing(c clash.Clash) ([]singbox.SingBoxOut, error) {
	sl := make([]singbox.SingBoxOut, 0, len(c.Proxies)+1)
	var jerr error
	for _, v := range c.Proxies {
		v := v
		s, t, err := comm(&v)
		if err != nil {
			jerr = errors.Join(jerr, err)
			continue
		}
		nsl, err := convertMap[t](&v, s)
		if err != nil {
			jerr = errors.Join(jerr, err)
			continue
		}
		sl = append(sl, nsl...)
	}
	return sl, jerr
}

var ErrNotSupportType = errors.New("不支持的类型")

var typeMap = map[string]string{
	"ss":        "shadowsocks",
	"ssr":       "shadowsocksr",
	"vmess":     "vmess",
	"vless":     "vless",
	"trojan":    "trojan",
	"socks5":    "socks",
	"http":      "http",
	"hysteria":  "hysteria",
	"wireguard": "wireguard",
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

	if p.Smux.Enabled {
		s.Multiplex = &singbox.SingMultiplex{
			Enabled: true,
			MaxConnections: func() int {
				if p.Smux.MaxStreams != 0 {
					return 0
				}
				return max(p.Smux.MaxConnections, 4)
			}(),
			MinStreams: p.Smux.MaxStreams,
			MaxStreams: func() int {
				if p.Smux.MaxStreams != 0 {
					return 0
				}
				return max(p.Smux.MinStreams, 4)
			}(),
			Padding:  p.Smux.Padding,
			Protocol: p.Smux.Protocol,
		}
	}

	return s, s.Type, nil
}
