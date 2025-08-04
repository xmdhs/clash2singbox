package convert

import (
	"fmt"

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
	s.ZeroRttHandshake = bool(p.ReduceRtt)
	s.Heartbeat = fmt.Sprintf("%vms", p.HeartbeatInterval)
	if p.IP != "" {
		s.Server = p.IP
	}
	return []singbox.SingBoxOut{*s}, nil
}
