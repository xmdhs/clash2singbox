package convert

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
)

func openvpnEndpoint(p *clash.Proxies) (*singbox.SingBoxEndpoint, error) {
	if strings.TrimSpace(p.CA) == "" {
		return nil, fmt.Errorf("openvpn: %w: ca is required", ErrNotSupportType)
	}
	if p.Dev != "" && strings.ToLower(strings.TrimSpace(p.Dev)) != "tun" {
		return nil, fmt.Errorf("openvpn: %w: unsupported dev %q, only tun is supported", ErrNotSupportType, p.Dev)
	}
	hasTLSAuth := strings.TrimSpace(p.TLSAuth) != ""
	hasTLSCrypt := strings.TrimSpace(p.TLSCrypt) != ""
	hasTLSCryptV2 := strings.TrimSpace(p.TLSCryptV2) != ""
	if hasTLSAuth && hasTLSCrypt {
		return nil, fmt.Errorf("openvpn: %w: tls-auth and tls-crypt are mutually exclusive", ErrNotSupportType)
	}
	if hasTLSCryptV2 && (hasTLSAuth || hasTLSCrypt) {
		return nil, fmt.Errorf("openvpn: %w: tls-crypt-v2 is mutually exclusive with tls-auth and tls-crypt", ErrNotSupportType)
	}
	if p.KeyDirection != "" && p.KeyDirection != "0" && p.KeyDirection != "1" {
		return nil, fmt.Errorf("openvpn: %w: unsupported key-direction %q", ErrNotSupportType, p.KeyDirection)
	}
	hasCert := strings.TrimSpace(p.Cert) != ""
	hasKey := strings.TrimSpace(p.Key) != ""
	if hasCert != hasKey {
		return nil, fmt.Errorf("openvpn: %w: cert and key must both be set", ErrNotSupportType)
	}
	if !hasCert && strings.TrimSpace(p.Username) == "" {
		return nil, fmt.Errorf("openvpn: %w: requires either cert+key or username", ErrNotSupportType)
	}
	if strings.TrimSpace(p.Server) == "" {
		return nil, fmt.Errorf("openvpn: %w: server is required", ErrNotSupportType)
	}
	port, err := strconv.Atoi(p.Port)
	if err != nil {
		return nil, fmt.Errorf("openvpn: %w", err)
	}

	ep := &singbox.SingBoxEndpoint{
		Type:       "openvpn-client",
		Tag:        p.Name,
		Server:     p.Server,
		ServerPort: port,
		Network:    normalizeOpenVPNProto(p.Proto),
		Mode:       "tls",
		MTU:        uint32(p.MTU),
		Detour:     p.DialerProxy,
	}

	if strings.TrimSpace(p.Username) != "" {
		ep.Username = p.Username
		ep.Password = p.Password
	}

	// data ciphers
	if len(p.DataCiphers) > 0 {
		ep.DataCiphers = append([]string(nil), p.DataCiphers...)
	} else if strings.TrimSpace(p.Cipher) != "" {
		normalized := normalizeOpenVPNCipher(p.Cipher)
		if normalized != "AES-128-GCM" {
			ep.DataCiphers = []string{normalized}
		}
	}
	if strings.TrimSpace(p.DataCipherFallback) != "" {
		ep.DataCiphersFallback = strings.TrimSpace(p.DataCipherFallback)
	}
	if strings.TrimSpace(p.Auth) != "" {
		ep.Auth = strings.TrimSpace(p.Auth)
	}
	if v := normalizeOpenVPNCompLZO(p.CompLZO); v != "" {
		ep.CompressionLZO = v
	}
	if int(p.Ping) > 0 {
		ep.PingInterval = strconv.Itoa(int(p.Ping)) + "s"
	}
	if int(p.PingRestart) > 0 {
		ep.PingRestart = strconv.Itoa(int(p.PingRestart)) + "s"
	}

	// TLS: CA is always required, client cert/key optional
	tls := &singbox.SingOpenVPNTLS{
		Certificate: []string{p.CA},
	}
	if hasCert {
		tls.ClientCertificate = []string{p.Cert}
		tls.ClientKey = []string{p.Key}
	}

	// control wrap: tls-auth / tls-crypt / tls-crypt-v2 (mutually exclusive, priority already validated)
	var cw *singbox.SingOpenVPNControlWrap
	switch {
	case hasTLSCryptV2:
		cw = &singbox.SingOpenVPNControlWrap{Type: "tls_crypt_v2", Key: []string{p.TLSCryptV2}}
	case hasTLSCrypt:
		cw = &singbox.SingOpenVPNControlWrap{Type: "tls_crypt", Key: []string{p.TLSCrypt}}
	case hasTLSAuth:
		cw = &singbox.SingOpenVPNControlWrap{Type: "tls_auth", Key: []string{p.TLSAuth}}
	}
	if cw != nil {
		// mihomo 0 -> client, 1 -> server; bidirectional when empty
		switch p.KeyDirection {
		case "0":
			cw.Direction = "client"
		case "1":
			cw.Direction = "server"
		default:
			cw.Direction = ""
		}
		tls.ControlWrap = cw
	}
	ep.TLS = tls

	return ep, nil
}

func normalizeOpenVPNProto(proto string) string {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "":
		return "udp"
	case "udp", "udp4":
		return "udp"
	case "tcp", "tcp-client", "tcp4", "tcp4-client":
		return "tcp"
	default:
		return strings.ToLower(strings.TrimSpace(proto))
	}
}

func normalizeOpenVPNCipher(cipher string) string {
	switch strings.ToUpper(strings.TrimSpace(cipher)) {
	case "":
		return "AES-128-GCM"
	case "AES-CBC":
		return "AES-128-CBC"
	default:
		return strings.ToUpper(strings.TrimSpace(cipher))
	}
}

func normalizeOpenVPNCompLZO(compLZO string) string {
	switch strings.ToLower(strings.TrimSpace(compLZO)) {
	case "yes", "adaptive":
		return "yes"
	case "no", "":
		return ""
	default:
		return strings.ToLower(strings.TrimSpace(compLZO))
	}
}
