package convert

import (
	"strconv"

	"github.com/xmdhs/clash2singbox/model"
	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
)

func tuic(p *clash.Proxies, s *singbox.SingBoxOut, _ model.SingBoxVer) ([]singbox.SingBoxOut, error) {
	p.Tls = true
	tls(p, s)
	s.UUID = p.Uuid
	s.CongestionController = p.CongestionController
	s.UdpRelayMode = p.UdpRelayMode
	s.UdpOverStream = bool(p.UdpOverStream)
	s.ZeroRttHandshake = bool(p.ReduceRtt)
	if p.HeartbeatInterval != 0 {
		s.Heartbeat = strconv.Itoa(int(p.HeartbeatInterval)) + "ms"
	}
	if p.IP != "" {
		s.Server = p.IP
	}
	return []singbox.SingBoxOut{*s}, nil
}
