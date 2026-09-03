package convert

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"sync"

	"github.com/xmdhs/clash2singbox/model"
	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
)

var convertMap = map[string]func(*clash.Proxies, *singbox.SingBoxOut, model.SingBoxVer) ([]singbox.SingBoxOut, error){
	"vmess":       oldConver(vmess),
	"vless":       oldConver(vless),
	"shadowsocks": ss,
	// "shadowsocksr": ss,
	"trojan":    oldConver(trojan),
	"http":      oldConver(httpOpts),
	"socks":     oldConver(socks5),
	"hysteria":  oldConver(hysteria),
	"hysteria2": hysteia2,
	"tuic":      tuic,
	"anytls":    anytls,
	"snell":     snell,
}

func oldConver(f func(*clash.Proxies, *singbox.SingBoxOut) error) func(*clash.Proxies, *singbox.SingBoxOut, model.SingBoxVer) ([]singbox.SingBoxOut, error) {
	return func(c *clash.Proxies, p *singbox.SingBoxOut, _ model.SingBoxVer) ([]singbox.SingBoxOut, error) {
		err := f(c, p)
		return []singbox.SingBoxOut{*p}, err
	}
}

// convertOne 转换单个节点：纯函数（只读入参拷贝），可并发调用。
// 返回 outs（普通 outbound）、ep（wireguard/openvpn endpoint），二者互斥；
// err 非空时调用方丢弃 outs/ep，与原串行语义一致。
func convertOne(v clash.Proxies, ver model.SingBoxVer) ([]singbox.SingBoxOut, *singbox.SingBoxEndpoint, error) {
	t := typeMap[v.Type]
	if t == "" {
		return nil, nil, fmt.Errorf("comm: %w %v", ErrNotSupportType, v.Type)
	}
	if t == "wireguard" {
		ep, err := wireguardEndpoint(&v)
		if err != nil {
			return nil, nil, err
		}
		return nil, ep, nil
	}
	if t == "openvpn-client" {
		ep, err := openvpnEndpoint(&v)
		if err != nil {
			return nil, nil, err
		}
		return nil, ep, nil
	}
	s, _, err := comm(&v)
	if err != nil {
		return nil, nil, err
	}
	fn := convertMap[t]
	if fn == nil {
		return nil, nil, fmt.Errorf("comm: %w %v", ErrNotSupportType, v.Type)
	}
	nsl, err := fn(&v, s, ver)
	if err != nil {
		return nil, nil, err
	}
	return nsl, nil, nil
}

// serialThreshold 以下节点数走串行，避免 goroutine 开销盖过实际工作。
const serialThreshold = 64

func Clash2sing(c clash.Clash, ver model.SingBoxVer) ([]singbox.SingBoxOut, []*singbox.SingBoxEndpoint, error) {
	n := len(c.Proxies)
	sl := make([]singbox.SingBoxOut, 0, n+1)
	var eps []*singbox.SingBoxEndpoint
	var jerr error
	if n < serialThreshold {
		for _, v := range c.Proxies {
			v := v
			outs, ep, err := convertOne(v, ver)
			if err != nil {
				jerr = errors.Join(jerr, err)
				continue
			}
			if ep != nil {
				eps = append(eps, ep)
				continue
			}
			sl = append(sl, outs...)
		}
	} else {
		// 按核分片并行转换，按下标写回以保序（输出顺序与输入一致，
		// 错误 Join 顺序也与串行一致）。
		workers := runtime.NumCPU()
		if workers < 2 {
			workers = 2
		}
		if workers > n {
			workers = n
		}
		outsList := make([][]singbox.SingBoxOut, n)
		epsList := make([]*singbox.SingBoxEndpoint, n)
		errs := make([]error, n)
		var wg sync.WaitGroup
		chunk := (n + workers - 1) / workers
		for w := 0; w < workers; w++ {
			start := w * chunk
			end := start + chunk
			if end > n {
				end = n
			}
			if start >= end {
				break
			}
			wg.Add(1)
			go func(start, end int) {
				defer wg.Done()
				for i := start; i < end; i++ {
					outs, ep, err := convertOne(c.Proxies[i], ver)
					outsList[i] = outs
					epsList[i] = ep
					errs[i] = err
				}
			}(start, end)
		}
		wg.Wait()
		for i := 0; i < n; i++ {
			if errs[i] != nil {
				jerr = errors.Join(jerr, errs[i])
				continue
			}
			if epsList[i] != nil {
				eps = append(eps, epsList[i])
				continue
			}
			sl = append(sl, outsList[i]...)
		}
	}
	slm := make(map[string]singbox.SingBoxOut, len(c.Proxies)+1)
	for _, v := range sl {
		slm[v.Tag] = v
	}
	for _, v := range c.ProxyGroup {
		if v.Type != "relay" {
			continue
		}
		l := relay(slm, v.Proxies, v.Name)
		sl = append(sl, l...)
	}

	return sl, eps, jerr
}

var ErrNotSupportType = errors.New("不支持的类型")

var typeMap = map[string]string{
	"ss": "shadowsocks",
	// "ssr":       "shadowsocksr",
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

func comm(p *clash.Proxies) (*singbox.SingBoxOut, string, error) {
	s := &singbox.SingBoxOut{}
	s.Type = typeMap[p.Type]
	if s.Type == "" {
		return nil, "", fmt.Errorf("comm: %w %v", ErrNotSupportType, p.Type)
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
			Enabled:    true,
			MaxStreams: int(p.Smux.MaxStreams),
			Padding:    bool(p.Smux.Padding),
			Protocol:   p.Smux.Protocol,
		}
		if p.Smux.MaxStreams == 0 {
			s.Multiplex.MinStreams = max(int(p.Smux.MinStreams), 4)
			s.Multiplex.MaxConnections = max(int(p.Smux.MaxConnections), 4)
		}
	}
	s.TcpFastOpen = p.Tfo
	s.TcpMultiPath = p.Mptcp

	return s, s.Type, nil
}
