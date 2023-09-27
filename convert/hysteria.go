package convert

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
)

func hysteria(p *clash.Proxies, s *singbox.SingBoxOut) error {
	p.Tls = true
	tls(p, s)
	if p.Port == "" {
		return fmt.Errorf("hysteria: %w", ErrNotSupportType)
	}
	if p.AuthStr != "" {
		s.AuthStr = p.AuthStr
	} else {
		s.AuthStr = p.AuthStr1
	}
	s.Obfs = &singbox.SingObfs{
		Value: p.Obfs,
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
		s.RecvWindow = p.RecvWindow
	} else {
		s.RecvWindow = p.RecvWindow1
	}
	if p.RecvWindowConn != 0 {
		s.RecvWindowConn = p.RecvWindowConn
	} else {
		s.RecvWindowConn = p.RecvWindowConn1
	}
	if p.CaStr != "" {
		s.TLS.Certificate = p.CaStr
	} else {
		s.TLS.Certificate = p.CaStr1
	}
	disableMtuDiscovery := false
	switch v := p.DisableMtuDiscovery.(type) {
	case int:
		if v == 1 {
			disableMtuDiscovery = true
		}
	case bool:
		if v {
			disableMtuDiscovery = true
		}
	}

	s.DisableMtuDiscovery = disableMtuDiscovery
	return nil
}

func hysteia2(p *clash.Proxies, s *singbox.SingBoxOut) ([]singbox.SingBoxOut, error) {
	p.Tls = true
	tls(p, s)
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
	s.Obfs = &singbox.SingObfs{
		Type:  p.Obfs,
		Value: p.ObfsPassword,
	}
	return []singbox.SingBoxOut{*s}, nil
}

func anyToMbps(s string) (int, error) {
	mbps, err := strconv.Atoi(s)
	if err == nil {
		return mbps, nil
	}
	sl := strings.Split(s, " ")
	if len(sl) != 2 {
		return 0, fmt.Errorf("anyToMbps: %w", ErrNotSupportType)
	}
	fStr := strings.ToTitle(string(sl[1][0]))

	n := 1.0
	switch fStr {
	case "K":
		n = 1.0 / 1000.0
	case "M":
		n = 1
	case "G":
		n = 1000
	case "T":
		n = 1000 * 1000
	}
	m, err := strconv.Atoi(sl[0])
	if err != nil {
		return 0, fmt.Errorf("anyToMbps: %w", ErrNotSupportType)
	}
	mb := int(float64(m) * n)
	if mb == 0 {
		mb = 1
	}
	return mb, nil
}
