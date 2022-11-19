package convert

import (
	"errors"
	"fmt"

	"github.com/xmdhs/clash2singbox/clash"
	"github.com/xmdhs/clash2singbox/singbox"
)

func Clash2sing(c clash.Clash) ([]singbox.SingBoxOut, error) {
	sl := make([]singbox.SingBoxOut, 0, len(c.Proxies)+1)
	for _, v := range c.Proxies {
		v := v
		s, t, err := comm(&v)
		if err != nil {
			return nil, fmt.Errorf("clash2sing: %w", err)
		}
		switch t {
		case "vmess":
			err = vmess(&v, s)
		case "shadowsocks":
			err = ss(&v, s)
		case "trojan":
			err = trojan(&v, s)
		}
		if err != nil {
			return nil, fmt.Errorf("clash2sing: %w", err)
		}
		sl = append(sl, *s)
	}
	return sl, nil
}

var ErrNotSupportType = errors.New("不支持的类型")

func comm(p *clash.Proxies) (*singbox.SingBoxOut, string, error) {
	s := &singbox.SingBoxOut{}
	switch p.Type {
	case "ss":
		s.Type = "shadowsocks"
	case "vmess":
		s.Type = "vmess"
	case "trojan":
		s.Type = "trojan"
	default:
		return nil, "", fmt.Errorf("comm: %w", ErrNotSupportType)
	}
	s.Tag = p.Name
	s.Server = p.Server
	s.ServerPort = p.Port
	s.Password = p.Password

	s.TLS.Enabled = p.Tls
	s.TLS.ServerName = p.Sni
	s.TLS.Insecure = p.SkipCertVerify

	return s, s.Type, nil
}

func vmess(p *clash.Proxies, s *singbox.SingBoxOut) error {
	s.AlterID = p.AlterId
	s.UUID = p.Uuid
	s.Security = p.Cipher
	if p.WsOpts.Path != "" {
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
	return fmt.Errorf("vmess: %w", ErrNotSupportType)
}

func trojan(p *clash.Proxies, s *singbox.SingBoxOut) error {
	s.TLS.Enabled = true
	if p.WsOpts.Path != "" {
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

func vmessWsOpts(p *clash.Proxies, s *singbox.SingBoxOut) error {
	s.Transport.Type = "ws"
	s.Transport.Headers = p.WsOpts.Headers
	s.Transport.Path = p.WsOpts.Path
	s.Transport.EarlyDataHeaderName = p.WsOpts.EarlyDataHeaderName
	s.Transport.MaxEarlyData = p.WsOpts.MaxEarlyData
	return nil
}

func vmessGrpcOpts(p *clash.Proxies, s *singbox.SingBoxOut) error {
	s.Transport.Type = "grpc"
	s.Transport.ServiceName = p.GrpcOpts.GrpcServiceName
	return nil
}

func ss(p *clash.Proxies, s *singbox.SingBoxOut) error {
	s.Method = p.Cipher
	return nil
}
