package convert

import (
	"fmt"

	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
)

func tls(p *clash.Proxies, s *singbox.SingBoxOut) {
	if p.Tls {
		s.TLS = &singbox.SingTLS{}
		s.TLS.Enabled = bool(p.Tls)
		s.TLS.DisableSNI = bool(p.DisableSni)
		if p.Servername != "" {
			s.TLS.ServerName = p.Servername
		} else if p.Sni != "" {
			s.TLS.ServerName = p.Sni
		} else {
			s.TLS.ServerName = p.Server
		}
		if p.ClientFingerprint != "" {
			s.TLS.Utls = &singbox.SingUtls{}
			s.TLS.Utls.Enabled = true
			s.TLS.Utls.Fingerprint = p.ClientFingerprint
		}
		s.TLS.Insecure = bool(p.SkipCertVerify)
		s.TLS.Alpn = p.Alpn
	}
	if p.RealityOpts.PublicKey != "" {
		if s.TLS == nil {
			s.TLS = &singbox.SingTLS{}
		}
		if s.TLS.Reality == nil {
			s.TLS.Reality = &singbox.SingReality{}
		}
		s.TLS.Reality.Enabled = true
		s.TLS.Reality.PublicKey = p.RealityOpts.PublicKey
		s.TLS.Reality.ShortID = p.RealityOpts.ShortId
	}
}

func vmess(p *clash.Proxies, s *singbox.SingBoxOut) error {
	tls(p, s)
	s.AlterID = int(p.AlterId)
	s.UUID = p.Uuid
	s.Security = p.Cipher
	s.GlobalPadding = bool(p.GlobalPadding)
	s.AuthenticatedLength = bool(p.AuthenticatedLength)
	s.PacketEncoding = packetEncodingValue(p)
	if p.WsOpts.Path != "" || p.Network == "ws" {
		vmessWsOpts(p, s)
		return nil
	}
	if p.GrpcOpts.GrpcServiceName != "" {
		vmessGrpcOpts(p, s)
		return nil
	}
	if p.H2Opts.Path != "" || p.Network == "h2" {
		vmessHttp2Opts(p, s)
		return nil
	}
	if p.Network == "http" || len(p.HTTPOpts.Path) > 0 || len(p.HTTPOpts.Headers) > 0 || p.HTTPOpts.Method != "" {
		vmessHttpOpts(p, s)
	}
	return nil
}

func vless(p *clash.Proxies, s *singbox.SingBoxOut) error {
	vmess(p, s)
	s.Security = ""
	s.GlobalPadding = false
	s.AuthenticatedLength = false
	s.PacketEncoding = packetEncodingValue(p)
	if p.Network != "ws" && p.Flow != "" {
		if p.Flow != "" && p.Flow != "xtls-rprx-vision" {
			return fmt.Errorf("vless: Flow %w", ErrNotSupportType)
		}
		s.Flow = p.Flow
	}
	return nil
}

func vmessWsOpts(p *clash.Proxies, s *singbox.SingBoxOut) {
	t := "ws"
	if p.WsOpts.V2rayHttpUpgrade {
		t = "httpupgrade"
	}
	if s.Transport == nil {
		s.Transport = &singbox.SingTransport{}
	}
	s.Transport.Type = t
	m := map[string][]string{}

	if len(p.WsHeaders) != 0 {
		for k, v := range p.WsHeaders {
			m[k] = []string{v}
		}
	} else {
		for k, v := range p.WsOpts.Headers {
			m[k] = []string{v}
		}
	}
	if p.WsOpts.V2rayHttpUpgrade {
		host := p.Servername
		if host == "" {
			host = p.WsOpts.Headers["Host"]
		}
		s.Transport.Host = host
	}
	s.Transport.Headers = m
	s.Transport.Path = p.WsOpts.Path
	s.Transport.EarlyDataHeaderName = p.WsOpts.EarlyDataHeaderName
	s.Transport.MaxEarlyData = int(p.WsOpts.MaxEarlyData)
}

func vmessGrpcOpts(p *clash.Proxies, s *singbox.SingBoxOut) {
	if s.Transport == nil {
		s.Transport = &singbox.SingTransport{}
	}
	s.Transport.Type = "grpc"
	s.Transport.ServiceName = p.GrpcOpts.GrpcServiceName
}

func vmessHttp2Opts(p *clash.Proxies, s *singbox.SingBoxOut) {
	if s.Transport == nil {
		s.Transport = &singbox.SingTransport{}
	}
	s.Transport.Type = "http"
	s.Transport.Host = p.H2Opts.Host
	s.Transport.Path = p.H2Opts.Path
}

func vmessHttpOpts(p *clash.Proxies, s *singbox.SingBoxOut) {
	if s.Transport == nil {
		s.Transport = &singbox.SingTransport{}
	}
	s.Transport.Type = "http"
	if len(p.HTTPOpts.Headers["Host"]) > 0 {
		s.Transport.Host = p.HTTPOpts.Headers["Host"]
	}
	if len(p.HTTPOpts.Path) > 0 {
		s.Transport.Path = p.HTTPOpts.Path[0]
	}
	s.Transport.Method = p.HTTPOpts.Method
	s.Transport.Headers = p.HTTPOpts.Headers
}

func packetEncodingValue(p *clash.Proxies) string {
	packetEncoding := p.PacketEncoding
	if packetEncoding == "" {
		packetEncoding = p.PacketEncoding1
	}
	if packetEncoding == "" {
		return ""
	}
	switch packetEncoding {
	case "packetaddr", "packet", "xudp":
		return packetEncoding
	default:
		return ""
	}
}

func trojan(p *clash.Proxies, s *singbox.SingBoxOut) error {
	p.Tls = true
	tls(p, s)
	if p.WsOpts.Path != "" || p.Network == "ws" {
		vmessWsOpts(p, s)
	}
	if p.GrpcOpts.GrpcServiceName != "" {
		vmessGrpcOpts(p, s)
	}
	return nil
}
