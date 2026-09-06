package convert

import (
	"cmp"
	"fmt"
	"math/rand/v2"
	"regexp"
	"strconv"
	"strings"

	"github.com/xmdhs/clash2singbox/model"
	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
)

func hysteria(p *clash.Proxies, s *singbox.SingBoxOut) error {
	tls(p, s, true)
	if p.Port == "" && p.Ports == "" {
		return fmt.Errorf("hysteria: %w", ErrNotSupportType)
	}
	if p.Ports != "" {
		ports, err := portsToPorts(p.Ports)
		if err != nil {
			return fmt.Errorf("hysteria: %w", err)
		}
		s.ServerPort = 0
		s.ServerPorts = ports
	}
	if p.Protocol != "udp" && p.Protocol != "" {
		return fmt.Errorf("hysteria: %w", ErrNotSupportType)
	}

	// Clash 同时接受 kebab-case 与 snake_case 两种写法
	s.AuthStr = cmp.Or(p.AuthStr, p.AuthStr1)
	s.RecvWindow = int(cmp.Or(p.RecvWindow, p.RecvWindow1))
	s.RecvWindowConn = int(cmp.Or(p.RecvWindowConn, p.RecvWindowConn1))
	if ca := cmp.Or(p.CaStr, p.CaStr1); ca != "" {
		s.TLS.Certificate = []string{ca}
	}
	if p.Obfs != "" {
		s.Obfs = &singbox.SingObfs{Value: p.Obfs}
	}
	// 速率是纯数字时按 Mbps 输出，否则原样保留带单位的写法
	if up, err := strconv.Atoi(p.Up); err == nil {
		s.UpMbps = up
	} else {
		s.Up = p.Up
	}
	if down, err := strconv.Atoi(p.Down); err == nil {
		s.DownMbps = down
	} else {
		s.Down = p.Down
	}
	s.DisableMtuDiscovery = bool(p.DisableMtuDiscovery)
	if p.HopInterval != 0 {
		s.HopInterval = strconv.Itoa(int(p.HopInterval)) + "s"
	}
	return nil
}

func hysteria2(p *clash.Proxies, s *singbox.SingBoxOut, ver model.SingBoxVer) ([]singbox.SingBoxOut, error) {
	tls(p, s, true)

	isRealm := bool(p.RealmOpts.Enable) && p.RealmOpts.ServerUrl != ""
	switch {
	case isRealm:
		// realm 模式由 realm 服务器分配地址，与 server / server_port(s) / hop_interval 互斥
		s.Server = ""
		s.ServerPort = 0
		s.Realm = &singbox.SingRealm{
			ServerUrl:   p.RealmOpts.ServerUrl,
			Token:       p.RealmOpts.Token,
			RealmId:     p.RealmOpts.RealmId,
			StunServers: p.RealmOpts.StunServers,
		}
	case p.Ports != "" && ver >= model.SING111:
		// sing-box 1.11 起支持 server_ports 端口跳跃
		ports, err := portsToPorts(p.Ports)
		if err != nil {
			return nil, fmt.Errorf("hysteria2: %w", err)
		}
		s.ServerPort = 0
		s.ServerPorts = ports
	case p.Ports != "":
		// 更早的版本只能从端口列表里随机挑一个
		port, err := portsToPort(p.Ports)
		if err != nil {
			return nil, fmt.Errorf("hysteria2: %w", err)
		}
		s.ServerPort = port
	}
	if !isRealm && p.HopInterval != 0 {
		s.HopInterval = strconv.Itoa(int(p.HopInterval)) + "s"
	}

	var err error
	if s.UpMbps, err = anyToMbps(p.Up); err != nil {
		return nil, fmt.Errorf("hysteria2: %w", err)
	}
	if s.DownMbps, err = anyToMbps(p.Down); err != nil {
		return nil, fmt.Errorf("hysteria2: %w", err)
	}
	if p.ObfsPassword != "" && p.Obfs != "" {
		s.Obfs = &singbox.SingObfs{Type: p.Obfs, Value: p.ObfsPassword}
	}
	return []singbox.SingBoxOut{*s}, nil
}

var rateStringRegexp = regexp.MustCompile(`^(\d+)\s*([KMGT]?)([Bb])ps$`)

// anyToMbps 把 Clash 的速率写法换算成 Mbps：纯数字直接视为 Mbps，
// 带单位的写法（如 "500 Kbps"、"1 GBps"）按单位换算，结果最小为 1。
func anyToMbps(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	if mb, err := strconv.Atoi(s); err == nil {
		return mb, nil
	}
	m := rateStringRegexp.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("anyToMbps: %w", ErrNotSupportType)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, fmt.Errorf("anyToMbps: %w", err)
	}
	scale := 1.0
	switch m[2] {
	case "K":
		scale = 1.0 / 1000
	case "G":
		scale = 1000
	case "T":
		scale = 1000 * 1000
	}
	if m[3] == "B" { // 字节换成比特
		scale *= 8
	}
	return max(int(float64(n)*scale), 1), nil
}

// splitPorts 把 Clash 的端口列表（如 "500-505,600/700"）拆成单个端口或区间。
func splitPorts(ports string) []string {
	return strings.FieldsFunc(ports, func(r rune) bool { return r == ',' || r == '/' })
}

// portRange 解析单个端口或 "start-end" 区间。
func portRange(s string) (start, end int, err error) {
	from, to, isRange := strings.Cut(s, "-")
	if !isRange {
		to = from
	}
	if start, err = strconv.Atoi(from); err != nil {
		return 0, 0, err
	}
	if end, err = strconv.Atoi(to); err != nil {
		return 0, 0, err
	}
	if end < start {
		return 0, 0, ErrNotSupportType
	}
	return start, end, nil
}

// portsToPort 从端口列表里随机挑一个端口，供不支持端口跳跃的旧版 sing-box 使用。
func portsToPort(ports string) (int, error) {
	list := splitPorts(ports)
	if len(list) == 0 {
		return 0, fmt.Errorf("portsToPort: %w", ErrNotSupportType)
	}
	start, end, err := portRange(list[rand.N(len(list))])
	if err != nil {
		return 0, fmt.Errorf("portsToPort: %w", err)
	}
	return start + rand.N(end-start+1), nil
}

// portsToPorts 把端口列表转成 sing-box server_ports 要求的 "start:end" 形式。
func portsToPorts(ports string) ([]string, error) {
	list := splitPorts(ports)
	out := make([]string, 0, len(list))
	for _, item := range list {
		start, end, err := portRange(item)
		if err != nil {
			return nil, fmt.Errorf("portsToPorts: %w", err)
		}
		out = append(out, strconv.Itoa(start)+":"+strconv.Itoa(end))
	}
	return out, nil
}
