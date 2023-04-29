package convert

import (
	"fmt"

	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
)

func tls(p *clash.Proxies, s *singbox.SingBoxOut) {
	if p.Tls {
		s.TLS = &singbox.SingTLS{}
		s.TLS.Enabled = p.Tls
		if p.Servername != "" {
			s.TLS.ServerName = p.Servername
		} else if p.Sni != "" {
			s.TLS.ServerName = p.Sni
		} else {
			s.TLS.ServerName = p.Server
		}
		s.TLS.Insecure = p.SkipCertVerify
	}
}

func vmess(p *clash.Proxies, s *singbox.SingBoxOut) error {
	tls(p, s)
	s.AlterID = p.AlterId
	s.UUID = p.Uuid
	s.Security = p.Cipher
	if p.WsOpts.Path != "" || p.Network == "ws" {
		err := vmessWsOpts(p, s)
		if err != nil {
			return fmt.Errorf("vmess: %w", err)
		}
		return nil
	}
	if p.GrpcOpts.GrpcServiceName != "" {
		err := vmessGrpcOpts(p, s)
		if err != nil {
			return fmt.Errorf("vmess: %w", err)
		}
		return nil
	}
	if p.H2Opts.Path != "" || p.Network == "h2" {
		err := vmessHttpOpts(p, s)
		if err != nil {
			return fmt.Errorf("vmess: %w", err)
		}
		return nil
	}
	return nil
}

func vmessWsOpts(p *clash.Proxies, s *singbox.SingBoxOut) error {
	if s.Transport == nil {
		s.Transport = &singbox.SingTransport{}
	}
	s.Transport.Type = "ws"
	s.Transport.Headers = p.WsOpts.Headers
	s.Transport.Path = p.WsOpts.Path
	s.Transport.EarlyDataHeaderName = p.WsOpts.EarlyDataHeaderName
	s.Transport.MaxEarlyData = p.WsOpts.MaxEarlyData
	return nil
}

func vmessGrpcOpts(p *clash.Proxies, s *singbox.SingBoxOut) error {
	if s.Transport == nil {
		s.Transport = &singbox.SingTransport{}
	}
	s.Transport.Type = "grpc"
	s.Transport.ServiceName = p.GrpcOpts.GrpcServiceName
	return nil
}

func vmessHttpOpts(p *clash.Proxies, s *singbox.SingBoxOut) error {
	if s.Transport == nil {
		s.Transport = &singbox.SingTransport{}
	}
	s.Transport.Type = "http"
	s.Transport.Host = p.H2Opts.Host
	s.Transport.Path = p.H2Opts.Path
	return nil
}

func trojan(p *clash.Proxies, s *singbox.SingBoxOut) error {
	if s.TLS == nil {
		s.TLS = &singbox.SingTLS{}
	}
	if p.Sni != "" {
		s.TLS.ServerName = p.Sni
	} else {
		s.TLS.ServerName = p.Server
	}
	s.TLS.Insecure = p.SkipCertVerify
	s.TLS.Enabled = true
	if p.WsOpts.Path != "" || p.Network == "ws" {
		err := vmessWsOpts(p, s)
		if err != nil {
			return fmt.Errorf("trojan: %w", err)
		}
	}
	if p.GrpcOpts.GrpcServiceName != "" {
		err := vmessGrpcOpts(p, s)
		if err != nil {
			return fmt.Errorf("trojan: %w", err)
		}
	}
	s.TLS.Alpn = p.Alpn
	return nil
}
