package convert

import (
	"fmt"
	"net/netip"

	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
	"golang.org/x/exp/constraints"
)

func wireguard(p *clash.Proxies, s *singbox.SingBoxOut) (o []singbox.SingBoxOut, err error) {
	s.LocalAddress = append(s.LocalAddress, p.IP, p.IPv6)
	s.LocalAddress, err = addCidr(s.LocalAddress)
	if err != nil {
		return nil, fmt.Errorf("wireguard: %w", err)
	}
	s.PeerPublicKey = p.PublicKey
	s.PreSharedKey = p.PreSharedKey
	s.PrivateKey = p.PrivateKey
	// Transform reserved array
	if p.Reserved != nil {
		s.Reserved = slicesConvert[uint8, int64](p.Reserved.Value)
	}
	// Dialer-proxy
	s.Detour = p.DialerProxy
	s.MTU = uint(p.MTU)
	// Multi-peers
	for _, peer := range p.Peers {
		var reserved []int64
		if peer.Reserved != nil {
			reserved = slicesConvert[uint8, int64](peer.Reserved.Value)
		}
		s.Peers = append(s.Peers, &singbox.SingWireguardMultiPeer{
			Server:       peer.Server,
			ServerPort:   peer.Port,
			PublicKey:    peer.PublicKey,
			PreSharedKey: peer.PreSharedKey,
			AllowedIps:   peer.AllowedIPs,
			Reserved:     reserved,
		})
	}
	return []singbox.SingBoxOut{*s}, nil
}

func slicesConvert[T constraints.Integer | constraints.Float, E constraints.Integer | constraints.Float](t []T) []E {
	e := make([]E, 0, len(t))
	for _, v := range t {
		e = append(e, E(v))
	}
	return e
}

func addCidr(ipl []string) ([]string, error) {
	c := make([]string, 0, len(ipl))
	for _, v := range ipl {
		p, err := netip.ParsePrefix(v)
		if err == nil {
			c = append(c, p.String())
		}
		ipr, err := netip.ParseAddr(v)
		if err != nil {
			return nil, fmt.Errorf("addCidr: %w", err)
		}
		if ipr.Is4() {
			c = append(c, netip.PrefixFrom(ipr, 32).String())
		}
		if ipr.Is6() {
			c = append(c, netip.PrefixFrom(ipr, 128).String())
		}
	}
	return c, nil
}
