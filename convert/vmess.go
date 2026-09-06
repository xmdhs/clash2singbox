package convert

import (
	"cmp"
	"fmt"

	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
)

// tls 按 Clash 节点的 TLS / Reality 配置填充 s.TLS。
// enabled 为 true 时开启 TLS；trojan、hysteria 等协议 TLS 必开，由调用方直接传 true。
func tls(p *clash.Proxies, s *singbox.SingBoxOut, enabled bool) {
	if enabled {
		s.TLS = &singbox.SingTLS{
			Enabled:    true,
			DisableSNI: bool(p.DisableSni),
			ServerName: cmp.Or(p.Servername, p.Sni, p.Server),
			Insecure:   bool(p.SkipCertVerify),
			Alpn:       p.Alpn,
		}
		if p.ClientFingerprint != "" {
			s.TLS.Utls = &singbox.SingUtls{Enabled: true, Fingerprint: p.ClientFingerprint}
		}
	}
	if p.RealityOpts.PublicKey != "" {
		if s.TLS == nil {
			s.TLS = &singbox.SingTLS{}
		}
		s.TLS.Reality = &singbox.SingReality{
			Enabled:   true,
			PublicKey: p.RealityOpts.PublicKey,
			ShortID:   p.RealityOpts.ShortId,
		}
	}
}

func vmess(p *clash.Proxies, s *singbox.SingBoxOut) error {
	tls(p, s, bool(p.Tls))
	s.AlterID = int(p.AlterId)
	s.UUID = p.Uuid
	s.Security = p.Cipher
	s.GlobalPadding = bool(p.GlobalPadding)
	s.AuthenticatedLength = bool(p.AuthenticatedLength)
	s.PacketEncoding = packetEncoding(p)
	transport(p, s)
	return nil
}

func vless(p *clash.Proxies, s *singbox.SingBoxOut) error {
	tls(p, s, bool(p.Tls))
	s.UUID = p.Uuid
	s.PacketEncoding = packetEncoding(p)
	transport(p, s)
	// flow 只对非 ws 传输有意义，且 sing-box 仅支持 xtls-rprx-vision
	if p.Network != "ws" && p.Flow != "" {
		if p.Flow != "xtls-rprx-vision" {
			return fmt.Errorf("vless: Flow %w", ErrNotSupportType)
		}
		s.Flow = p.Flow
	}
	return nil
}

func trojan(p *clash.Proxies, s *singbox.SingBoxOut) error {
	tls(p, s, true)
	if p.WsOpts.Path != "" || p.Network == "ws" {
		wsTransport(p, s)
	}
	if p.GrpcOpts.GrpcServiceName != "" {
		grpcTransport(p, s)
	}
	return nil
}

// transport 按 Clash 的 network 与各 *-opts 选择传输层，优先级 ws > grpc > h2 > http。
func transport(p *clash.Proxies, s *singbox.SingBoxOut) {
	switch {
	case p.WsOpts.Path != "" || p.Network == "ws":
		wsTransport(p, s)
	case p.GrpcOpts.GrpcServiceName != "":
		grpcTransport(p, s)
	case p.H2Opts.Path != "" || p.Network == "h2":
		h2Transport(p, s)
	case p.Network == "http" || len(p.HTTPOpts.Path) > 0 || len(p.HTTPOpts.Headers) > 0 || p.HTTPOpts.Method != "":
		httpTransport(p, s)
	}
}

// ensureTransport 返回 s 的传输层配置，不存在时创建。trojan 允许 ws 与 grpc 叠加设置，因此需要复用已有对象。
func ensureTransport(s *singbox.SingBoxOut) *singbox.SingTransport {
	if s.Transport == nil {
		s.Transport = &singbox.SingTransport{}
	}
	return s.Transport
}

func wsTransport(p *clash.Proxies, s *singbox.SingBoxOut) {
	t := ensureTransport(s)
	t.Type = "ws"
	t.Path = p.WsOpts.Path
	t.EarlyDataHeaderName = p.WsOpts.EarlyDataHeaderName
	t.MaxEarlyData = int(p.WsOpts.MaxEarlyData)

	// 旧版 Clash 的顶层 ws-headers 优先于 ws-opts.headers
	headers := p.WsOpts.Headers
	if len(p.WsHeaders) != 0 {
		headers = p.WsHeaders
	}
	t.Headers = make(map[string][]string, len(headers))
	for k, v := range headers {
		t.Headers[k] = []string{v}
	}
	if p.WsOpts.V2rayHttpUpgrade {
		t.Type = "httpupgrade"
		t.Host = cmp.Or(p.Servername, p.WsOpts.Headers["Host"])
	}
}

func grpcTransport(p *clash.Proxies, s *singbox.SingBoxOut) {
	t := ensureTransport(s)
	t.Type = "grpc"
	t.ServiceName = p.GrpcOpts.GrpcServiceName
}

func h2Transport(p *clash.Proxies, s *singbox.SingBoxOut) {
	t := ensureTransport(s)
	t.Type = "http"
	t.Host = p.H2Opts.Host
	t.Path = p.H2Opts.Path
}

func httpTransport(p *clash.Proxies, s *singbox.SingBoxOut) {
	t := ensureTransport(s)
	t.Type = "http"
	if len(p.HTTPOpts.Headers["Host"]) > 0 {
		t.Host = p.HTTPOpts.Headers["Host"]
	}
	if len(p.HTTPOpts.Path) > 0 {
		t.Path = p.HTTPOpts.Path[0]
	}
	t.Method = p.HTTPOpts.Method
	t.Headers = p.HTTPOpts.Headers
}

// packetEncoding 返回 sing-box 支持的 packet_encoding 值；Clash 的 packet-encoding 与 packet_encoding 两种写法都接受。
func packetEncoding(p *clash.Proxies) string {
	switch v := cmp.Or(p.PacketEncoding, p.PacketEncoding1); v {
	case "packetaddr", "packet", "xudp":
		return v
	}
	return ""
}
