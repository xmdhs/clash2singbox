package convert

import (
	"strconv"

	"github.com/xmdhs/clash2singbox/model"
	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
)

func anytls(p *clash.Proxies, s *singbox.SingBoxOut, v model.SingBoxVer) ([]singbox.SingBoxOut, error) {
	p.Tls = true
	tls(p, s)
	s.TcpFastOpen = false

	if p.IdleSessionCheckInterval != 0 {
		s.IdleSessionCheckInterval = strconv.Itoa(int(p.IdleSessionCheckInterval)) + "s"
	}
	if p.IdleSessionTimeout != 0 {
		s.IdleSessionTimeout = strconv.Itoa(int(p.IdleSessionTimeout)) + "s"
	}
	if p.MinIdleSession != 0 {
		s.MinIdleSession = int(p.MinIdleSession)
	}
	return []singbox.SingBoxOut{*s}, nil
}
