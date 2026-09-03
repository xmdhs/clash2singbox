package convert

import (
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
	p.Tls = true
	tls(p, s)
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
	if p.AuthStr != "" {
		s.AuthStr = p.AuthStr
	} else {
		s.AuthStr = p.AuthStr1
	}
	if p.Obfs != "" {
		s.Obfs = &singbox.SingObfs{
			Value: p.Obfs,
		}
	}
	s.TLS.Alpn = p.Alpn
	if p.Protocol != "udp" && p.Protocol != "" {
		return fmt.Errorf("hysteria: %w", ErrNotSupportType)
	}
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
	if p.RecvWindow != 0 {
		s.RecvWindow = int(p.RecvWindow)
	} else {
		s.RecvWindow = int(p.RecvWindow1)
	}
	if p.RecvWindowConn != 0 {
		s.RecvWindowConn = int(p.RecvWindowConn)
	} else {
		s.RecvWindowConn = int(p.RecvWindowConn1)
	}
	if p.CaStr != "" {
		s.TLS.Certificate = []string{p.CaStr}
	} else if p.CaStr1 != "" {
		s.TLS.Certificate = []string{p.CaStr1}
	}
	s.DisableMtuDiscovery = bool(p.DisableMtuDiscovery)
	if p.HopInterval != 0 {
		s.HopInterval = strconv.Itoa(int(p.HopInterval)) + "s"
	}
	return nil
}

func hysteia2(p *clash.Proxies, s *singbox.SingBoxOut, v model.SingBoxVer) ([]singbox.SingBoxOut, error) {
	p.Tls = true
	tls(p, s)

	isRealm := bool(p.RealmOpts.Enable) && p.RealmOpts.ServerUrl != ""
	if isRealm {
		// realm 与 server / server_port / server_ports 互斥
		s.Server = ""
		s.ServerPort = 0
		s.ServerPorts = nil
		s.HopInterval = ""
		s.Realm = &singbox.SingRealm{
			ServerUrl:   p.RealmOpts.ServerUrl,
			Token:       p.RealmOpts.Token,
			RealmId:     p.RealmOpts.RealmId,
			StunServers: p.RealmOpts.StunServers,
		}
	} else {
		if p.Ports != "" {
			// sing-box 1.11.0 起支持 hysteria2 的 server_ports / hop_interval
			if v >= model.SING111 {
				var err error
				s.ServerPort = 0
				s.ServerPorts, err = portsToPorts(p.Ports)
				if err != nil {
					return nil, fmt.Errorf("hysteia2: %w", err)
				}
			} else {
				port, err := portsToPort(p.Ports)
				if err != nil {
					return nil, fmt.Errorf("hysteia2: %w", err)
				}
				s.ServerPort = port
			}
		}
		if p.HopInterval != 0 {
			s.HopInterval = strconv.Itoa(int(p.HopInterval)) + "s"
		}
	}

	var err error
	s.UpMbps, err = anyToMbps(p.Up)
	if err != nil {
		return nil, fmt.Errorf("hysteia2: %w", err)
	}
	s.DownMbps, err = anyToMbps(p.Down)
	if err != nil {
		return nil, fmt.Errorf("hysteia2: %w", err)
	}
	s.Password = p.Password
	if p.ObfsPassword != "" && p.Obfs != "" {
		s.Obfs = &singbox.SingObfs{
			Type:  p.Obfs,
			Value: p.ObfsPassword,
		}
	}
	return []singbox.SingBoxOut{*s}, nil
}

var rateStringRegexp = regexp.MustCompile(`^(\d+)\s*([KMGT]?)([Bb])ps$`)

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

	n := 1.0
	switch m[2] {
	case "K":
		n = 1.0 / 1000.0
	case "M":
		n = 1
	case "G":
		n = 1000
	case "T":
		n = 1000 * 1000
	}
	if m[3] == "B" {
		n = n * 8.0
	}
	// 正则已保证 m[1] 为纯数字，Atoi 不会失败
	v, _ := strconv.Atoi(m[1])
	mb := int(float64(v) * n)
	if mb == 0 {
		mb = 1
	}
	return mb, nil
}

func portsToPort(ports string) (int, error) {
	portsList := []string{}
	for _, tmp := range strings.Split(ports, ",") {
		portsList = append(portsList, strings.Split(tmp, "/")...)
	}
	portStr := portsList[rand.N(len(portsList))]
	if l := strings.Split(portStr, "-"); len(l) == 2 {
		endPort, err := strconv.Atoi(l[1])
		if err != nil {
			return 0, fmt.Errorf("portsToPort: %w", err)
		}
		startPort, err := strconv.Atoi(l[0])
		if err != nil {
			return 0, fmt.Errorf("portsToPort: %w", err)
		}
		if endPort < startPort {
			return 0, fmt.Errorf("portsToPort: %w", ErrNotSupportType)
		}
		return rand.N(endPort-startPort+1) + startPort, nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("portsToPort: %w", err)
	}
	return port, nil
}

func portsToPorts(ports string) ([]string, error) {
	portsList := []string{}
	for _, tmp := range strings.Split(ports, ",") {
		portsList = append(portsList, strings.Split(tmp, "/")...)
	}
	pl := []string{}
	for _, v := range portsList {
		if l := strings.Split(v, "-"); len(l) == 2 {
			endPort, err := strconv.Atoi(l[1])
			if err != nil {
				return nil, fmt.Errorf("portsToPorts: %w", err)
			}
			startPort, err := strconv.Atoi(l[0])
			if err != nil {
				return nil, fmt.Errorf("portsToPorts: %w", err)
			}
			if endPort < startPort {
				return nil, fmt.Errorf("portsToPorts: %w", ErrNotSupportType)
			}
			pl = append(pl, strconv.Itoa(startPort)+":"+strconv.Itoa(endPort))
		} else {
			pl = append(pl, v+":"+v)
		}
	}
	return pl, nil
}
