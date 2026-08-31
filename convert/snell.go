package convert

import (
	"fmt"

	"github.com/xmdhs/clash2singbox/model"
	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
)

func snell(p *clash.Proxies, s *singbox.SingBoxOut, _ model.SingBoxVer) ([]singbox.SingBoxOut, error) {
	if p.Psk == "" {
		return nil, fmt.Errorf("snell %s: missing psk", p.Name)
	}

	ver := int(p.Version)
	var outVer int
	switch ver {
	case 4:
		outVer = 4
	case 5:
		outVer = 4
	case 6:
		outVer = 6
	default:
		return nil, fmt.Errorf("snell %s: unsupported version %d", p.Name, ver)
	}

	s.Psk = p.Psk
	s.Version = outVer

	if outVer == 4 {
		if p.Reuse {
			s.Reuse = true
		}
		if p.ObfsOpts != nil {
			mode := p.ObfsOpts.Mode
			switch mode {
			case "", "none":
				// no obfs
			case "http", "tls":
				s.ObfsMode = mode
				host := p.ObfsOpts.Host
				if host == "" {
					host = "bing.com"
				}
				s.ObfsHost = host
			case "shadow-tls", "restls", "jls":
				return nil, fmt.Errorf("snell %s: obfs mode %s not supported by sing-box", p.Name, mode)
			default:
				return nil, fmt.Errorf("snell %s: obfs mode %s not supported by sing-box", p.Name, mode)
			}
		}
	}
	// version 6: ignore reuse and obfs-opts entirely

	return []singbox.SingBoxOut{*s}, nil
}
