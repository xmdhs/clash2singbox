package convert

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xmdhs/clash2singbox/model"
	"github.com/xmdhs/clash2singbox/model/clash"
	"gopkg.in/yaml.v3"
)

func Test_portsToPorts(t *testing.T) {
	_, err := portsToPorts("443-43")
	assert.Error(t, err)

	port, _ := portsToPorts("443-500")
	t.Log(port)

	port, err = portsToPorts("443-500/200-300,100-120/123")
	t.Log(port)
	assert.Nil(t, err)

	_, err = portsToPorts("100-100")
	assert.Nil(t, err)

}

func TestHysteriaSinglePort(t *testing.T) {
	p := &clash.Proxies{
		Type:   "hysteria",
		Name:   "hy",
		Server: "example.com",
		Port:   "443",
		Up:     "10",
		Down:   "20",
	}
	s, err := comm(p)
	assert.NoError(t, err)
	err = hysteria(p, s)
	assert.NoError(t, err)
	assert.Equal(t, 443, s.ServerPort)
	assert.Empty(t, s.ServerPorts)
}

func TestHysteriaServerPortsAndHopInterval(t *testing.T) {
	p := &clash.Proxies{
		Type:        "hysteria",
		Name:        "hy",
		Server:      "example.com",
		Port:        "443",
		Ports:       "500-505,600",
		Up:          "10",
		Down:        "20",
		HopInterval: 15,
	}
	s, err := comm(p)
	assert.NoError(t, err)
	err = hysteria(p, s)
	assert.NoError(t, err)
	assert.Equal(t, 0, s.ServerPort)
	assert.Equal(t, []string{"500:505", "600:600"}, s.ServerPorts)
	assert.Equal(t, "15s", s.HopInterval)
}

func TestHysteria2ServerPortsAndHopInterval(t *testing.T) {
	p := &clash.Proxies{
		Type:        "hysteria2",
		Name:        "hy2",
		Server:      "example.com",
		Port:        "443",
		Ports:       "700-701",
		Up:          "10",
		Down:        "20",
		HopInterval: 30,
	}
	s, err := comm(p)
	assert.NoError(t, err)
	// server_ports / hop_interval 自 sing-box 1.11.0 起支持
	out, err := hysteria2(p, s, model.SINGLATEST)
	assert.NoError(t, err)
	assert.Len(t, out, 1)
	assert.Equal(t, 0, out[0].ServerPort)
	assert.Equal(t, []string{"700:701"}, out[0].ServerPorts)
	assert.Equal(t, "30s", out[0].HopInterval)
}

func TestHysteria2SinglePortBelow111(t *testing.T) {
	p := &clash.Proxies{
		Type:   "hysteria2",
		Name:   "hy2",
		Server: "example.com",
		Port:   "443",
		Ports:  "700-701",
		Up:     "10",
		Down:   "20",
	}
	s, err := comm(p)
	assert.NoError(t, err)
	// sing-box < 1.11.0 不支持 server_ports，退化为随机单端口
	out, err := hysteria2(p, s, model.SING110)
	assert.NoError(t, err)
	assert.Len(t, out, 1)
	assert.Equal(t, []string(nil), out[0].ServerPorts)
	assert.GreaterOrEqual(t, out[0].ServerPort, 700)
	assert.LessOrEqual(t, out[0].ServerPort, 701)
}

func TestParseTuicURL(t *testing.T) {
	p, err := ParseURL("tuic://user-uuid:secret@example.com:443?disable-sni=1&udp-over-stream=1#node")
	assert.NoError(t, err)
	assert.Equal(t, "user-uuid", p.Uuid)
	assert.Equal(t, "secret", p.Password)
	assert.True(t, bool(p.DisableSni))
	assert.True(t, bool(p.UdpOverStream))
}

func TestTrojanFingerprintUsesClientFingerprint(t *testing.T) {
	p, err := ParseURL("trojan://pass@example.com:443?fp=chrome#node")
	assert.NoError(t, err)
	assert.Equal(t, "chrome", p.ClientFingerprint)
}

func TestClash2singWireguardEndpoint(t *testing.T) {
	c := clash.Clash{
		Proxies: []clash.Proxies{{
			Type:       "wireguard",
			Name:       "wg",
			Server:     "example.com",
			Port:       "51820",
			PrivateKey: "privkey",
			PublicKey:  "pubkey",
			IP:         "10.0.0.1",
		}},
	}
	out, eps, err := Clash2sing(c, model.SINGLATEST)
	assert.NoError(t, err)
	assert.Empty(t, out)
	assert.Len(t, eps, 1)
	assert.Equal(t, "wireguard", eps[0].Type)
	assert.Equal(t, "wg", eps[0].Tag)
	assert.Equal(t, "privkey", eps[0].PrivateKey)
	assert.Len(t, eps[0].Peers, 1)
	assert.Equal(t, "example.com", eps[0].Peers[0].Address)
	assert.Equal(t, uint16(51820), eps[0].Peers[0].Port)
	assert.Equal(t, "pubkey", eps[0].Peers[0].PublicKey)
}

func TestAnytlsDisablesTCPFastOpen(t *testing.T) {
	p := &clash.Proxies{
		Type:     "anytls",
		Name:     "a",
		Server:   "example.com",
		Port:     "443",
		Password: "pass",
		Tfo:      true,
	}
	s, err := comm(p)
	assert.NoError(t, err)
	out, err := anytls(p, s, model.SINGLATEST)
	assert.NoError(t, err)
	assert.False(t, out[0].TcpFastOpen)
}

func TestVmessHTTPTransportDetection(t *testing.T) {
	p := &clash.Proxies{
		Type:    "vmess",
		Name:    "v",
		Server:  "example.com",
		Port:    "443",
		Uuid:    "uuid",
		Network: "http",
	}
	assert.NoError(t, yaml.Unmarshal([]byte("http-opts:\n  path: [/test]\n"), p))
	s, err := comm(p)
	assert.NoError(t, err)
	err = vmess(p, s)
	assert.NoError(t, err)
	assert.NotNil(t, s.Transport)
	assert.Equal(t, "http", s.Transport.Type)
	assert.Equal(t, "/test", s.Transport.Path)
}

func TestVmessFields(t *testing.T) {
	p := &clash.Proxies{
		Type:                "vmess",
		Name:                "v",
		Server:              "example.com",
		Port:                "443",
		Uuid:                "uuid",
		GlobalPadding:       true,
		AuthenticatedLength: true,
		PacketEncoding:      "packetaddr",
	}
	s, err := comm(p)
	assert.NoError(t, err)
	err = vmess(p, s)
	assert.NoError(t, err)
	assert.True(t, s.GlobalPadding)
	assert.True(t, s.AuthenticatedLength)
	assert.Equal(t, "packetaddr", s.PacketEncoding)
}

func TestVlessPacketEncodingCompatibility(t *testing.T) {
	p := &clash.Proxies{
		Type:            "vless",
		Name:            "v",
		Server:          "example.com",
		Port:            "443",
		Uuid:            "uuid",
		PacketEncoding1: "xudp",
	}
	s, err := comm(p)
	assert.NoError(t, err)
	err = vless(p, s)
	assert.NoError(t, err)
	assert.Equal(t, "xudp", s.PacketEncoding)
}
