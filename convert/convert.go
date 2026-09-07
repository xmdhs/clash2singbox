package convert

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/xmdhs/clash2singbox/model"
	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
)

var ErrNotSupportType = errors.New("不支持的类型")

// typeMap 把 Clash 节点的 type 映射为 sing-box 的 outbound / endpoint 类型。
var typeMap = map[string]string{
	"ss":        "shadowsocks",
	"vmess":     "vmess",
	"vless":     "vless",
	"trojan":    "trojan",
	"socks5":    "socks",
	"http":      "http",
	"hysteria":  "hysteria",
	"hysteria2": "hysteria2",
	"wireguard": "wireguard",
	"openvpn":   "openvpn-client",
	"tuic":      "tuic",
	"anytls":    "anytls",
	"snell":     "snell",
}

// converter 把 Clash 节点 p 的协议字段填入已由 comm 初始化好通用字段的 s。
// 少数协议会拆出多个 outbound（如 shadow-tls 插件），因此返回切片。
type converter func(p *clash.Proxies, s *singbox.SingBoxOut, ver model.SingBoxVer) ([]singbox.SingBoxOut, error)

// convertMap 以 sing-box 类型为键；wireguard / openvpn-client 是 endpoint，在 convertOne 中单独处理。
var convertMap = map[string]converter{
	"vmess":       single(vmess),
	"vless":       single(vless),
	"shadowsocks": ss,
	"trojan":      single(trojan),
	"http":        single(httpOpts),
	"socks":       single(socks5),
	"hysteria":    single(hysteria),
	"hysteria2":   hysteria2,
	"tuic":        tuic,
	"anytls":      anytls,
	"snell":       snell,
}

// single 适配只产出一个 outbound 且不区分 sing-box 版本的转换函数。
func single(f func(*clash.Proxies, *singbox.SingBoxOut) error) converter {
	return func(p *clash.Proxies, s *singbox.SingBoxOut, _ model.SingBoxVer) ([]singbox.SingBoxOut, error) {
		if err := f(p, s); err != nil {
			return nil, err
		}
		return []singbox.SingBoxOut{*s}, nil
	}
}

// Clash2sing 把 Clash 节点转换为 sing-box outbounds，wireguard / openvpn 节点转换为 endpoints。
// 单个节点失败不影响其他节点，所有错误汇总在返回的 error 中；relay 类型的 proxy-group 会展开成链式 outbound。
func Clash2sing(c clash.Clash, ver model.SingBoxVer) ([]singbox.SingBoxOut, []*singbox.SingBoxEndpoint, error) {
	outs := make([]singbox.SingBoxOut, 0, len(c.Proxies))
	var eps []*singbox.SingBoxEndpoint
	var errs []error
	for i := range c.Proxies {
		nodeOuts, ep, err := convertOne(&c.Proxies[i], ver)
		switch {
		case err != nil:
			errs = append(errs, err)
		case ep != nil:
			eps = append(eps, ep)
		default:
			outs = append(outs, nodeOuts...)
		}
	}

	var byTag map[string]singbox.SingBoxOut
	for _, g := range c.ProxyGroup {
		if g.Type == "relay" {
			if byTag == nil {
				byTag = make(map[string]singbox.SingBoxOut, len(outs))
				for _, v := range outs {
					byTag[v.Tag] = v
				}
			}
			outs = append(outs, relay(byTag, g.Proxies, g.Name)...)
		}
	}
	return outs, eps, errors.Join(errs...)
}

// convertOne 转换单个节点：wireguard / openvpn 返回 endpoint，其他协议返回一个或多个 outbound。
func convertOne(p *clash.Proxies, ver model.SingBoxVer) ([]singbox.SingBoxOut, *singbox.SingBoxEndpoint, error) {
	switch typeMap[p.Type] {
	case "":
		return nil, nil, fmt.Errorf("comm: %w %v", ErrNotSupportType, p.Type)
	case "wireguard":
		ep, err := wireguardEndpoint(p)
		return nil, ep, err
	case "openvpn-client":
		ep, err := openvpnEndpoint(p)
		return nil, ep, err
	}
	s, err := comm(p)
	if err != nil {
		return nil, nil, err
	}
	outs, err := convertMap[s.Type](p, s, ver)
	return outs, nil, err
}

// comm 用 Clash 节点的通用字段（名称、服务器、端口、密码、smux、tfo、mptcp）初始化一个 outbound。
func comm(p *clash.Proxies) (*singbox.SingBoxOut, error) {
	typ := typeMap[p.Type]
	if typ == "" {
		return nil, fmt.Errorf("comm: %w %v", ErrNotSupportType, p.Type)
	}
	port, err := strconv.Atoi(p.Port)
	if err != nil {
		return nil, fmt.Errorf("comm: %w", err)
	}
	s := &singbox.SingBoxOut{
		Type:         typ,
		Tag:          p.Name,
		Server:       p.Server,
		ServerPort:   port,
		Password:     p.Password,
		TcpFastOpen:  p.Tfo,
		TcpMultiPath: p.Mptcp,
	}
	if p.Smux.Enabled {
		s.Multiplex = &singbox.SingMultiplex{
			Enabled:    true,
			MaxStreams: int(p.Smux.MaxStreams),
			Padding:    bool(p.Smux.Padding),
			Protocol:   p.Smux.Protocol,
		}
		// 未限制 max-streams 时，给连接数与最小流数一个下限，避免 sing-box 只开一条连接
		if p.Smux.MaxStreams == 0 {
			s.Multiplex.MinStreams = max(int(p.Smux.MinStreams), 4)
			s.Multiplex.MaxConnections = max(int(p.Smux.MaxConnections), 4)
		}
	}
	return s, nil
}
