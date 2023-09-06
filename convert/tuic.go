package convert

import (
	"fmt"

	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
)

func tuic(p *clash.Proxies, s *singbox.SingBoxOut) ([]singbox.SingBoxOut, error) {
	p.Tls = true
	tls(p, s)
	s.CongestionController = p.CongestionController
	s.UdpRelayMode = p.UdpRelayMode
	s.ZeroRttHandshake = p.ReduceRtt
	s.Heartbeat = fmt.Sprintf("%vms", p.HeartbeatInterval)
	return []singbox.SingBoxOut{*s}, nil
}
