package convert

import (
	"fmt"

	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
)

func wireguard(p *clash.Proxies, s *singbox.SingBoxOut) ([]singbox.SingBoxOut, error) {
	s.SystemInterface = false
	s.LocalAddress = append(s.LocalAddress, p.IP, p.IPv6)
	s.PeerPublicKey = p.PublicKey
	s.PreSharedKey = p.PreSharedKey
	s.PrivateKey = p.PrivateKey
	// Transform reserved array
	var reserved [3]uint8
	if len(p.Reserved) > 0 {
		if len(p.Reserved) != 3 {
			return nil, fmt.Errorf("invalid reserved value, required 3 bytes, got ", len(p.Reserved))
		}
		copy(reserved[:], p.Reserved[:])
		s.Reserved = reserved[:]
	}
	// Dialer-proxy
	s.Detour = p.DialerProxy
	// Multi-peers
	for i, peer := range p.Peers {
		var reserved [3]uint8
		if len(peer.Reserved) > 0 {
			if len(peer.Reserved) != 3 {
				return nil, fmt.Errorf("invalid reserved value, required 3 bytes, got ", len(p.Reserved))
			}
			copy(reserved[:], peer.Reserved[:])
		}
		s.Peers[i] = &singbox.SingWireguardMultiPeer{
			Server:       peer.Server,
			ServerPort:   peer.Port,
			PublicKey:    peer.PublicKey,
			PreSharedKey: peer.PreSharedKey,
			AllowedIps:   peer.AllowedIPs,
			Reserved:     reserved[:],
		}
	}
	return []singbox.SingBoxOut{*s}, nil
}
