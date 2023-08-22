package convert

import (
	"fmt"
	"strconv"

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
	s.Obfs = p.Obfs
	s.TLS.Alpn = p.Alpn
	if p.Protocol != "udp" || p.Protocol == "" {
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
