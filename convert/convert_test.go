package convert

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmdhs/clash2singbox/model"
	"github.com/xmdhs/clash2singbox/model/clash"
	"gopkg.in/yaml.v3"
)

func proxyFromYAML(t *testing.T, s string) clash.Proxies {
	t.Helper()
	p := clash.Proxies{}
	require.NoError(t, yaml.Unmarshal([]byte(s), &p))
	return p
}

// --- VMess ---

func TestVmessBasic(t *testing.T) {
	p := proxyFromYAML(t, `
name: vmess-node
type: vmess
server: 1.2.3.4
port: "443"
uuid: test-uuid
cipher: auto
alterId: 2
`)
	s, typ, err := comm(&p)
	require.NoError(t, err)
	assert.Equal(t, "vmess", typ)
	err = vmess(&p, s)
	require.NoError(t, err)
	assert.Equal(t, "test-uuid", s.UUID)
	assert.Equal(t, "auto", s.Security)
	assert.Equal(t, 2, s.AlterID)
	assert.Nil(t, s.TLS)
	assert.Nil(t, s.Transport)
}

func TestVmessTLS(t *testing.T) {
	p := proxyFromYAML(t, `
name: v
type: vmess
server: example.com
port: "443"
uuid: uuid
tls: true
sni: sni.example.com
skip-cert-verify: true
client-fingerprint: chrome
alpn: [h2, http/1.1]
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = vmess(&p, s)
	require.NoError(t, err)

	require.NotNil(t, s.TLS)
	assert.True(t, s.TLS.Enabled)
	assert.Equal(t, "sni.example.com", s.TLS.ServerName)
	assert.True(t, s.TLS.Insecure)
	assert.Equal(t, []string{"h2", "http/1.1"}, s.TLS.Alpn)
	require.NotNil(t, s.TLS.Utls)
	assert.True(t, s.TLS.Utls.Enabled)
	assert.Equal(t, "chrome", s.TLS.Utls.Fingerprint)
}

func TestVmessRealityTLS(t *testing.T) {
	p := proxyFromYAML(t, `
name: v
type: vmess
server: example.com
port: "443"
uuid: uuid
reality-opts:
  public-key: pub-key
  short-id: short-id
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = vmess(&p, s)
	require.NoError(t, err)

	require.NotNil(t, s.TLS)
	require.NotNil(t, s.TLS.Reality)
	assert.True(t, s.TLS.Reality.Enabled)
	assert.Equal(t, "pub-key", s.TLS.Reality.PublicKey)
	assert.Equal(t, "short-id", s.TLS.Reality.ShortID)
}

func TestVmessWSTransport(t *testing.T) {
	p := proxyFromYAML(t, `
name: v
type: vmess
server: example.com
port: "443"
uuid: uuid
network: ws
ws-opts:
  path: /ws
  headers:
    Host: ws.example.com
  early-data-header-name: Sec-WebSocket-Protocol
  max-early-data: 2048
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = vmess(&p, s)
	require.NoError(t, err)

	require.NotNil(t, s.Transport)
	assert.Equal(t, "ws", s.Transport.Type)
	assert.Equal(t, "/ws", s.Transport.Path)
	assert.Equal(t, map[string][]string{"Host": {"ws.example.com"}}, s.Transport.Headers)
	assert.Equal(t, "Sec-WebSocket-Protocol", s.Transport.EarlyDataHeaderName)
	assert.Equal(t, 2048, s.Transport.MaxEarlyData)
}

func TestVmessHttpUpgradeTransport(t *testing.T) {
	p := proxyFromYAML(t, `
name: v
type: vmess
server: example.com
port: "443"
uuid: uuid
servername: upgrade.example.com
ws-opts:
  path: /upgrade
  v2ray-http-upgrade: true
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = vmess(&p, s)
	require.NoError(t, err)

	require.NotNil(t, s.Transport)
	assert.Equal(t, "httpupgrade", s.Transport.Type)
	assert.Equal(t, "upgrade.example.com", s.Transport.Host)
}

func TestVmessGrpcTransport(t *testing.T) {
	p := proxyFromYAML(t, `
name: v
type: vmess
server: example.com
port: "443"
uuid: uuid
grpc-opts:
  grpc-service-name: my-grpc-svc
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = vmess(&p, s)
	require.NoError(t, err)

	require.NotNil(t, s.Transport)
	assert.Equal(t, "grpc", s.Transport.Type)
	assert.Equal(t, "my-grpc-svc", s.Transport.ServiceName)
}

func TestVmessH2Transport(t *testing.T) {
	p := proxyFromYAML(t, `
name: v
type: vmess
server: example.com
port: "443"
uuid: uuid
network: h2
h2-opts:
  host: [h2.example.com]
  path: /h2
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = vmess(&p, s)
	require.NoError(t, err)

	require.NotNil(t, s.Transport)
	assert.Equal(t, "http", s.Transport.Type)
	assert.Equal(t, "/h2", s.Transport.Path)
	assert.Equal(t, []string{"h2.example.com"}, s.Transport.Host)
}

func TestVmessPacketEncodingInvalid(t *testing.T) {
	p := proxyFromYAML(t, `
name: v
type: vmess
server: example.com
port: "443"
uuid: uuid
packet-encoding: invalid
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = vmess(&p, s)
	require.NoError(t, err)
	assert.Equal(t, "", s.PacketEncoding)
}

// --- VLESS ---

func TestVlessBasic(t *testing.T) {
	p := proxyFromYAML(t, `
name: vless-node
type: vless
server: example.com
port: "443"
uuid: uuid
tls: true
flow: xtls-rprx-vision
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = vless(&p, s)
	require.NoError(t, err)

	assert.Equal(t, "uuid", s.UUID)
	assert.Equal(t, "xtls-rprx-vision", s.Flow)
	assert.Equal(t, "", s.Security)
	assert.False(t, s.GlobalPadding)
	assert.False(t, s.AuthenticatedLength)
}

func TestVlessFlowNotSetOnWS(t *testing.T) {
	p := proxyFromYAML(t, `
name: v
type: vless
server: example.com
port: "443"
uuid: uuid
network: ws
flow: xtls-rprx-vision
ws-opts:
  path: /ws
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = vless(&p, s)
	require.NoError(t, err)
	assert.Equal(t, "", s.Flow)
}

func TestVlessUnsupportedFlowError(t *testing.T) {
	p := proxyFromYAML(t, `
name: v
type: vless
server: example.com
port: "443"
uuid: uuid
flow: xtls-rprx-direct
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = vless(&p, s)
	assert.Error(t, err)
}

// --- Trojan ---

func TestTrojanBasic(t *testing.T) {
	p := proxyFromYAML(t, `
name: trojan-node
type: trojan
server: example.com
port: "443"
password: pass
sni: sni.example.com
`)
	s, typ, err := comm(&p)
	require.NoError(t, err)
	assert.Equal(t, "trojan", typ)
	err = trojan(&p, s)
	require.NoError(t, err)

	assert.Equal(t, "pass", s.Password)
	require.NotNil(t, s.TLS)
	assert.True(t, s.TLS.Enabled)
	assert.Equal(t, "sni.example.com", s.TLS.ServerName)
}

func TestTrojanWSTransport(t *testing.T) {
	p := proxyFromYAML(t, `
name: t
type: trojan
server: example.com
port: "443"
password: pass
network: ws
ws-opts:
  path: /trojan-ws
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = trojan(&p, s)
	require.NoError(t, err)

	require.NotNil(t, s.Transport)
	assert.Equal(t, "ws", s.Transport.Type)
	assert.Equal(t, "/trojan-ws", s.Transport.Path)
}

func TestTrojanGrpcTransport(t *testing.T) {
	p := proxyFromYAML(t, `
name: t
type: trojan
server: example.com
port: "443"
password: pass
grpc-opts:
  grpc-service-name: trojan-grpc
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = trojan(&p, s)
	require.NoError(t, err)

	require.NotNil(t, s.Transport)
	assert.Equal(t, "grpc", s.Transport.Type)
	assert.Equal(t, "trojan-grpc", s.Transport.ServiceName)
}

// --- Shadowsocks ---

func TestSSBasic(t *testing.T) {
	p := proxyFromYAML(t, `
name: ss-node
type: ss
server: example.com
port: "8388"
password: pass
cipher: aes-256-gcm
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	out, err := ss(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, "aes-256-gcm", out[0].Method)
	assert.Equal(t, "pass", out[0].Password)
	assert.Nil(t, out[0].UdpOverTcp)
}

func TestSSNoSSRFieldsLeaked(t *testing.T) {
	p := proxyFromYAML(t, `
name: ss-node
type: ss
server: example.com
port: "8388"
password: pass
cipher: aes-256-gcm
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	out, err := ss(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	require.Len(t, out, 1)

	b, err := json.Marshal(out[0])
	require.NoError(t, err)
	jsonStr := string(b)
	assert.NotContains(t, jsonStr, "protocol")
	assert.NotContains(t, jsonStr, "protocol_param")
	assert.NotContains(t, jsonStr, "obfs_param")
}

func TestSSUdpOverTcp(t *testing.T) {
	p := proxyFromYAML(t, `
name: ss-uot
type: ss
server: example.com
port: "8388"
password: pass
cipher: aes-256-gcm
udp-over-tcp: true
udp-over-tcp-version: 2
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	out, err := ss(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	require.NotNil(t, out[0].UdpOverTcp)
	assert.True(t, out[0].UdpOverTcp.Enabled)
	assert.Equal(t, 2, out[0].UdpOverTcp.Version)
}

func TestSSObfsPlugin(t *testing.T) {
	p := proxyFromYAML(t, `
name: ss-obfs
type: ss
server: example.com
port: "8388"
cipher: aes-256-gcm
password: pass
plugin: obfs
plugin-opts:
  mode: http
  host: obfs.example.com
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	out, err := ss(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, "obfs-local", out[0].Plugin)
	assert.Contains(t, out[0].PluginOpts, "obfs=http")
	assert.Contains(t, out[0].PluginOpts, "obfs-host=obfs.example.com")
}

func TestSSShadowTlsPlugin(t *testing.T) {
	p := proxyFromYAML(t, `
name: ss-stls
type: ss
server: example.com
port: "443"
cipher: aes-256-gcm
password: pass
plugin: shadow-tls
plugin-opts:
  host: stls.example.com
  password: stls-pass
  version: 3
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	out, err := ss(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	require.Len(t, out, 2)

	assert.Equal(t, "ss-stls-shadowtls", out[0].Detour)
	assert.Equal(t, "", out[0].Server)
	assert.Equal(t, 0, out[0].ServerPort)

	assert.Equal(t, "shadowtls", out[1].Type)
	assert.Equal(t, "ss-stls-shadowtls", out[1].Tag)
	assert.Equal(t, "example.com", out[1].Server)
	assert.Equal(t, 443, out[1].ServerPort)
	assert.Equal(t, 3, out[1].Version)
	assert.Equal(t, "stls-pass", out[1].Password)
	require.NotNil(t, out[1].TLS)
	assert.Equal(t, "stls.example.com", out[1].TLS.ServerName)
}

// --- Hysteria ---

func TestHysteriaSpeedMbps(t *testing.T) {
	p := proxyFromYAML(t, `
name: hy
type: hysteria
server: example.com
port: "443"
up: "50"
down: "100"
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = hysteria(&p, s)
	require.NoError(t, err)
	assert.Equal(t, 50, s.UpMbps)
	assert.Equal(t, 100, s.DownMbps)
	assert.Equal(t, "", s.Up)
	assert.Equal(t, "", s.Down)
}

func TestHysteriaSpeedString(t *testing.T) {
	p := proxyFromYAML(t, `
name: hy
type: hysteria
server: example.com
port: "443"
up: "50 Mbps"
down: "100 Mbps"
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = hysteria(&p, s)
	require.NoError(t, err)
	assert.Equal(t, 0, s.UpMbps)
	assert.Equal(t, 0, s.DownMbps)
	assert.Equal(t, "50 Mbps", s.Up)
	assert.Equal(t, "100 Mbps", s.Down)
}

func TestHysteriaAuthStr(t *testing.T) {
	p := proxyFromYAML(t, `
name: hy
type: hysteria
server: example.com
port: "443"
up: "10"
down: "20"
auth-str: my-auth
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = hysteria(&p, s)
	require.NoError(t, err)
	assert.Equal(t, "my-auth", s.AuthStr)
}

func TestHysteriaObfs(t *testing.T) {
	p := proxyFromYAML(t, `
name: hy
type: hysteria
server: example.com
port: "443"
up: "10"
down: "20"
obfs: xplus-obfs-pass
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = hysteria(&p, s)
	require.NoError(t, err)
	require.NotNil(t, s.Obfs)
	assert.Equal(t, "xplus-obfs-pass", s.Obfs.Value)
}

func TestHysteriaCertificate(t *testing.T) {
	p := proxyFromYAML(t, `
name: hy
type: hysteria
server: example.com
port: "443"
up: "10"
down: "20"
ca-str: PEM-CERT-DATA
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = hysteria(&p, s)
	require.NoError(t, err)
	require.NotNil(t, s.TLS)
	assert.Equal(t, []string{"PEM-CERT-DATA"}, s.TLS.Certificate)
}

func TestHysteriaCertificateNotSetWhenEmpty(t *testing.T) {
	p := proxyFromYAML(t, `
name: hy
type: hysteria
server: example.com
port: "443"
up: "10"
down: "20"
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = hysteria(&p, s)
	require.NoError(t, err)
	require.NotNil(t, s.TLS)
	assert.Nil(t, s.TLS.Certificate)
}

func TestHysteriaRejectsNonUDPProtocol(t *testing.T) {
	p := proxyFromYAML(t, `
name: hy
type: hysteria
server: example.com
port: "443"
up: "10"
down: "20"
protocol: faketcp
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = hysteria(&p, s)
	assert.Error(t, err)
}

func TestHysteriaRecvWindow(t *testing.T) {
	p := proxyFromYAML(t, `
name: hy
type: hysteria
server: example.com
port: "443"
up: "10"
down: "20"
recv-window: 1024
recv-window-conn: 512
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = hysteria(&p, s)
	require.NoError(t, err)
	assert.Equal(t, 1024, s.RecvWindow)
	assert.Equal(t, 512, s.RecvWindowConn)
}

// --- Hysteria2 ---

func TestHysteria2Basic(t *testing.T) {
	p := proxyFromYAML(t, `
name: hy2
type: hysteria2
server: example.com
port: "443"
password: hy2-pass
up: "50"
down: "100"
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	out, err := hysteia2(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, "hy2-pass", out[0].Password)
	assert.Equal(t, 50, out[0].UpMbps)
	assert.Equal(t, 100, out[0].DownMbps)
	require.NotNil(t, out[0].TLS)
	assert.True(t, out[0].TLS.Enabled)
}

func TestHysteria2SpeedWithUnit(t *testing.T) {
	p := proxyFromYAML(t, `
name: hy2
type: hysteria2
server: example.com
port: "443"
password: pass
up: "100Mbps"
down: "1Gbps"
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	out, err := hysteia2(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	assert.Equal(t, 100, out[0].UpMbps)
	assert.Equal(t, 1000, out[0].DownMbps)
}

func TestHysteria2ObfsWithType(t *testing.T) {
	p := proxyFromYAML(t, `
name: hy2
type: hysteria2
server: example.com
port: "443"
password: pass
obfs: salamander
obfs-password: obfs-pass
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	out, err := hysteia2(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	require.NotNil(t, out[0].Obfs)
	b, _ := json.Marshal(out[0].Obfs)
	assert.Contains(t, string(b), `"type":"salamander"`)
	assert.Contains(t, string(b), `"password":"obfs-pass"`)
}

func TestHysteria2ObfsIgnoredWhenTypeEmpty(t *testing.T) {
	p := proxyFromYAML(t, `
name: hy2
type: hysteria2
server: example.com
port: "443"
password: pass
obfs-password: obfs-pass
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	out, err := hysteia2(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	assert.Nil(t, out[0].Obfs)
}

// --- Hysteria2 Realm ---

func TestHysteria2RealmEnabled(t *testing.T) {
	p := proxyFromYAML(t, `
name: hy2
type: hysteria2
server: server.com
port: "443"
password: pass
up: "30 Mbps"
down: "200 Mbps"
sni: server.com
realm-opts:
  enable: true
  server-url: https://realm.hy2.io
  token: public
  realm-id: my-cabin-1f3a8c2e9b
  stun-servers:
    - stun.nextcloud.com:3478
    - stun.sip.us:3478
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	out, err := hysteia2(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.NotNil(t, out[0].Realm)
	assert.Equal(t, "https://realm.hy2.io", out[0].Realm.ServerUrl)
	assert.Equal(t, "public", out[0].Realm.Token)
	assert.Equal(t, "my-cabin-1f3a8c2e9b", out[0].Realm.RealmId)
	assert.Equal(t, []string{"stun.nextcloud.com:3478", "stun.sip.us:3478"}, out[0].Realm.StunServers)
	// 与 realm 互斥的字段必须被清空
	assert.Equal(t, "", out[0].Server)
	assert.Equal(t, 0, out[0].ServerPort)
	assert.Empty(t, out[0].ServerPorts)
	assert.Equal(t, "", out[0].HopInterval)
	// 其他字段仍正常映射
	assert.Equal(t, "pass", out[0].Password)
	assert.Equal(t, 30, out[0].UpMbps)
	assert.Equal(t, 200, out[0].DownMbps)
	require.NotNil(t, out[0].TLS)

	b, err := json.Marshal(out[0])
	require.NoError(t, err)
	jsonStr := string(b)
	assert.Contains(t, jsonStr, `"realm"`)
	assert.Contains(t, jsonStr, `"server_url":"https://realm.hy2.io"`)
	assert.Contains(t, jsonStr, `"realm_id":"my-cabin-1f3a8c2e9b"`)
	assert.NotContains(t, jsonStr, `"server":`)
	assert.NotContains(t, jsonStr, `"server_port":`)
}

func TestHysteria2RealmWithoutToken(t *testing.T) {
	p := proxyFromYAML(t, `
name: hy2
type: hysteria2
server: example.com
port: "443"
password: pass
realm-opts:
  enable: true
  server-url: https://realm.hy2.io
  realm-id: rid-123
  stun-servers:
    - stun.example.com:3478
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	out, err := hysteia2(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	require.NotNil(t, out[0].Realm)
	assert.Equal(t, "", out[0].Realm.Token)
	b, err := json.Marshal(out[0])
	require.NoError(t, err)
	assert.NotContains(t, string(b), `"token"`)
}

func TestHysteria2RealmDisabledKeepsServer(t *testing.T) {
	p := proxyFromYAML(t, `
name: hy2
type: hysteria2
server: server.com
port: "443"
password: pass
realm-opts:
  enable: false
  server-url: https://realm.hy2.io
  token: public
  realm-id: rid
  stun-servers:
    - stun.example.com:3478
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	out, err := hysteia2(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	assert.Nil(t, out[0].Realm)
	assert.Equal(t, "server.com", out[0].Server)
	assert.Equal(t, 443, out[0].ServerPort)
}

func TestHysteria2RealmEmptyServerURLNotTriggered(t *testing.T) {
	p := proxyFromYAML(t, `
name: hy2
type: hysteria2
server: server.com
port: "443"
password: pass
realm-opts:
  enable: true
  realm-id: rid
  stun-servers:
    - stun.example.com:3478
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	out, err := hysteia2(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	assert.Nil(t, out[0].Realm)
	assert.Equal(t, "server.com", out[0].Server)
}

func TestHysteria2RealmIgnoresPortsAndHopInterval(t *testing.T) {
	p := proxyFromYAML(t, `
name: hy2
type: hysteria2
server: server.com
port: "443"
ports: 443-8443
hop-interval: 30
password: pass
realm-opts:
  enable: true
  server-url: https://realm.hy2.io
  token: t
  realm-id: rid
  stun-servers:
    - stun.example.com:3478
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	out, err := hysteia2(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	assert.Empty(t, out[0].ServerPorts)
	assert.Equal(t, "", out[0].HopInterval)
	assert.Equal(t, 0, out[0].ServerPort)
	require.NotNil(t, out[0].Realm)
}

func TestHysteria2RealmViaClash2sing(t *testing.T) {
	c := clash.Clash{}
	require.NoError(t, yaml.Unmarshal([]byte(`
proxies:
  - name: hy2-realm
    type: hysteria2
    server: server.com
    port: "443"
    password: pass
    realm-opts:
      enable: true
      server-url: https://realm.hy2.io
      token: public
      realm-id: rid
      stun-servers: ["stun.example.com:3478"]
  - name: hy2-direct
    type: hysteria2
    server: direct.com
    port: "443"
    password: pass
`), &c))
	out, _, err := Clash2sing(c, model.SINGLATEST)
	require.NoError(t, err)
	require.Len(t, out, 2)
	// 顺序与输入一致，realm 节点在前
	var realmOut, directOut *struct {
		Tag   string
		Realm interface{}
	}
	_ = realmOut
	_ = directOut
	for i := range out {
		if out[i].Tag == "hy2-realm" {
			require.NotNil(t, out[i].Realm)
			assert.Equal(t, "", out[i].Server)
		}
		if out[i].Tag == "hy2-direct" {
			assert.Nil(t, out[i].Realm)
			assert.Equal(t, "direct.com", out[i].Server)
		}
	}
}

// --- TUIC ---

func TestTuicBasic(t *testing.T) {
	p := proxyFromYAML(t, `
name: tuic-node
type: tuic
server: example.com
port: "443"
uuid: tuic-uuid
password: tuic-pass
congestion-controller: bbr
udp-relay-mode: native
reduce-rtt: true
heartbeat-interval: 10000
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	out, err := tuic(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	require.Len(t, out, 1)

	assert.Equal(t, "tuic-uuid", out[0].UUID)
	assert.Equal(t, "tuic-pass", out[0].Password)
	assert.Equal(t, "bbr", out[0].CongestionController)
	assert.Equal(t, "native", out[0].UdpRelayMode)
	assert.True(t, out[0].ZeroRttHandshake)
	assert.Equal(t, "10000ms", out[0].Heartbeat)
	require.NotNil(t, out[0].TLS)
	assert.True(t, out[0].TLS.Enabled)
}

func TestTuicCongestionControlJSONTag(t *testing.T) {
	p := proxyFromYAML(t, `
name: tuic-node
type: tuic
server: example.com
port: "443"
uuid: uuid
password: pass
congestion-controller: cubic
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	out, err := tuic(&p, s, model.SINGLATEST)
	require.NoError(t, err)

	b, err := json.Marshal(out[0])
	require.NoError(t, err)
	assert.Contains(t, string(b), `"congestion_control":"cubic"`)
}

func TestTuicIPOverridesServer(t *testing.T) {
	p := proxyFromYAML(t, `
name: tuic-node
type: tuic
server: example.com
port: "443"
uuid: uuid
password: pass
ip: 1.2.3.4
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	out, err := tuic(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	assert.Equal(t, "1.2.3.4", out[0].Server)
}

func TestTuicUdpOverStream(t *testing.T) {
	p := proxyFromYAML(t, `
name: tuic-node
type: tuic
server: example.com
port: "443"
uuid: uuid
password: pass
udp-over-stream: true
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	out, err := tuic(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	assert.True(t, out[0].UdpOverStream)
}

func TestTuicDisableSni(t *testing.T) {
	p := proxyFromYAML(t, `
name: tuic-node
type: tuic
server: example.com
port: "443"
uuid: uuid
password: pass
disable-sni: true
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	out, err := tuic(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	require.NotNil(t, out[0].TLS)
	assert.True(t, out[0].TLS.DisableSNI)
}

// --- WireGuard ---

func TestWireguardSinglePeer(t *testing.T) {
	p := proxyFromYAML(t, `
name: wg-node
type: wireguard
server: wg.example.com
port: "51820"
private-key: priv-key
public-key: pub-key
pre-shared-key: psk
ip: 10.0.0.2
ipv6: "fd00::2"
reserved: [1, 2, 3]
mtu: 1280
`)
	ep, err := wireguardEndpoint(&p)
	require.NoError(t, err)

	assert.Equal(t, "wireguard", ep.Type)
	assert.Equal(t, "wg-node", ep.Tag)
	assert.Equal(t, "priv-key", ep.PrivateKey)
	assert.Equal(t, uint32(1280), ep.MTU)
	assert.Equal(t, []string{"10.0.0.2/32", "fd00::2/128"}, ep.Address)

	require.Len(t, ep.Peers, 1)
	assert.Equal(t, "wg.example.com", ep.Peers[0].Address)
	assert.Equal(t, uint16(51820), ep.Peers[0].Port)
	assert.Equal(t, "pub-key", ep.Peers[0].PublicKey)
	assert.Equal(t, "psk", ep.Peers[0].PreSharedKey)
	assert.Equal(t, []uint8{1, 2, 3}, ep.Peers[0].Reserved)
}

func TestWireguardMultiPeer(t *testing.T) {
	p := proxyFromYAML(t, `
name: wg-multi
type: wireguard
server: wg.example.com
port: "51820"
private-key: priv-key
ip: "10.0.0.2/32"
peers:
  - server: peer1.example.com
    port: 51821
    public-key: pub1
    reserved: [4, 5, 6]
    allowed_ips: ["0.0.0.0/0"]
  - server: peer2.example.com
    port: 51822
    public-key: pub2
`)
	ep, err := wireguardEndpoint(&p)
	require.NoError(t, err)

	assert.Equal(t, []string{"10.0.0.2/32"}, ep.Address)
	require.Len(t, ep.Peers, 2)

	assert.Equal(t, "peer1.example.com", ep.Peers[0].Address)
	assert.Equal(t, uint16(51821), ep.Peers[0].Port)
	assert.Equal(t, "pub1", ep.Peers[0].PublicKey)
	assert.Equal(t, []uint8{4, 5, 6}, ep.Peers[0].Reserved)
	assert.Equal(t, []string{"0.0.0.0/0"}, ep.Peers[0].AllowedIps)

	assert.Equal(t, "peer2.example.com", ep.Peers[1].Address)
	assert.Equal(t, uint16(51822), ep.Peers[1].Port)
}

func TestWireguardDialerProxy(t *testing.T) {
	p := proxyFromYAML(t, `
name: wg
type: wireguard
server: example.com
port: "51820"
private-key: priv
public-key: pub
ip: 10.0.0.1
dialer-proxy: proxy-out
`)
	ep, err := wireguardEndpoint(&p)
	require.NoError(t, err)
	assert.Equal(t, "proxy-out", ep.Detour)
}

func TestWireguardEndpointJSON(t *testing.T) {
	p := proxyFromYAML(t, `
name: wg
type: wireguard
server: example.com
port: "51820"
private-key: priv
public-key: pub
ip: 10.0.0.1
reserved: [0, 0, 0]
`)
	ep, err := wireguardEndpoint(&p)
	require.NoError(t, err)

	b, err := json.Marshal(ep)
	require.NoError(t, err)
	jsonStr := string(b)

	assert.Contains(t, jsonStr, `"address":["10.0.0.1/32"]`)
	assert.Contains(t, jsonStr, `"private_key":"priv"`)
	assert.NotContains(t, jsonStr, "local_address")
	assert.NotContains(t, jsonStr, "peer_public_key")
	assert.NotContains(t, jsonStr, "server_port")
}

// --- Socks5 / HTTP ---

func TestSocks5Basic(t *testing.T) {
	p := proxyFromYAML(t, `
name: socks-node
type: socks5
server: example.com
port: "1080"
username: user
password: pass
`)
	s, typ, err := comm(&p)
	require.NoError(t, err)
	assert.Equal(t, "socks", typ)
	err = socks5(&p, s)
	require.NoError(t, err)
	assert.Equal(t, "user", s.Username)
	assert.Equal(t, "pass", s.Password)
	assert.Nil(t, s.TLS)
}

func TestSocks5WithTLS(t *testing.T) {
	p := proxyFromYAML(t, `
name: socks-tls
type: socks5
server: example.com
port: "1080"
username: user
password: pass
tls: true
sni: socks.example.com
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = socks5(&p, s)
	require.NoError(t, err)
	require.NotNil(t, s.TLS)
	assert.True(t, s.TLS.Enabled)
	assert.Equal(t, "socks.example.com", s.TLS.ServerName)
}

func TestHttpBasic(t *testing.T) {
	p := proxyFromYAML(t, `
name: http-node
type: http
server: example.com
port: "8080"
username: user
password: pass
`)
	s, typ, err := comm(&p)
	require.NoError(t, err)
	assert.Equal(t, "http", typ)
	err = httpOpts(&p, s)
	require.NoError(t, err)
	assert.Equal(t, "user", s.Username)
}

// --- AnyTLS ---

func TestAnytlsBasic(t *testing.T) {
	p := proxyFromYAML(t, `
name: anytls-node
type: anytls
server: example.com
port: "443"
password: pass
sni: anytls.example.com
idle-session-check-interval: 30
idle-session-timeout: 60
min-idle-session: 3
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	out, err := anytls(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	require.Len(t, out, 1)

	assert.Equal(t, "pass", out[0].Password)
	assert.Equal(t, "30s", out[0].IdleSessionCheckInterval)
	assert.Equal(t, "60s", out[0].IdleSessionTimeout)
	assert.Equal(t, 3, out[0].MinIdleSession)
	require.NotNil(t, out[0].TLS)
	assert.True(t, out[0].TLS.Enabled)
	assert.Equal(t, "anytls.example.com", out[0].TLS.ServerName)
}

// --- comm / shared ---

func TestCommSmux(t *testing.T) {
	p := proxyFromYAML(t, `
name: v
type: vmess
server: example.com
port: "443"
smux:
  enabled: true
  max-streams: 8
  padding: true
  protocol: h2mux
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	require.NotNil(t, s.Multiplex)
	assert.True(t, s.Multiplex.Enabled)
	assert.Equal(t, 8, s.Multiplex.MaxStreams)
	assert.True(t, s.Multiplex.Padding)
	assert.Equal(t, "h2mux", s.Multiplex.Protocol)
}

func TestCommTfoMptcp(t *testing.T) {
	p := proxyFromYAML(t, `
name: v
type: vmess
server: example.com
port: "443"
tfo: true
mptcp: true
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	assert.True(t, s.TcpFastOpen)
	assert.True(t, s.TcpMultiPath)
}

func TestCommUnsupportedType(t *testing.T) {
	p := proxyFromYAML(t, `
name: n
type: unknown
server: example.com
port: "443"
`)
	_, _, err := comm(&p)
	assert.Error(t, err)
}

// --- TLS ServerName priority ---

func TestTLSServerNamePriority(t *testing.T) {
	p := proxyFromYAML(t, `
name: v
type: vmess
server: example.com
port: "443"
tls: true
servername: first.example.com
sni: second.example.com
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = vmess(&p, s)
	require.NoError(t, err)
	assert.Equal(t, "first.example.com", s.TLS.ServerName)
}

func TestTLSServerNameFallbackToSni(t *testing.T) {
	p := proxyFromYAML(t, `
name: v
type: vmess
server: example.com
port: "443"
tls: true
sni: sni.example.com
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = vmess(&p, s)
	require.NoError(t, err)
	assert.Equal(t, "sni.example.com", s.TLS.ServerName)
}

func TestTLSServerNameFallbackToServer(t *testing.T) {
	p := proxyFromYAML(t, `
name: v
type: vmess
server: example.com
port: "443"
tls: true
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	err = vmess(&p, s)
	require.NoError(t, err)
	assert.Equal(t, "example.com", s.TLS.ServerName)
}

// --- anyToMbps ---

func TestAnyToMbps(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"", 0},
		{"100", 100},
		{"100Mbps", 100},
		{"1Gbps", 1000},
		{"500Kbps", 1},
		{"100MBps", 800},
	}
	for _, tt := range tests {
		v, err := anyToMbps(tt.input)
		assert.NoError(t, err, "input: %s", tt.input)
		assert.Equal(t, tt.expected, v, "input: %s", tt.input)
	}
}

func TestAnyToMbpsInvalid(t *testing.T) {
	_, err := anyToMbps("invalid")
	assert.Error(t, err)
}

// --- Clash2sing integration ---

func TestClash2singMixedTypes(t *testing.T) {
	c := clash.Clash{}
	require.NoError(t, yaml.Unmarshal([]byte(`
proxies:
  - name: vmess1
    type: vmess
    server: 1.1.1.1
    port: "443"
    uuid: uuid
  - name: wg1
    type: wireguard
    server: 2.2.2.2
    port: "51820"
    private-key: priv
    public-key: pub
    ip: 10.0.0.1
  - name: trojan1
    type: trojan
    server: 3.3.3.3
    port: "443"
    password: pass
`), &c))

	out, eps, err := Clash2sing(c, model.SINGLATEST)
	require.NoError(t, err)

	assert.Len(t, out, 2)
	assert.Equal(t, "vmess1", out[0].Tag)
	assert.Equal(t, "trojan1", out[1].Tag)

	require.Len(t, eps, 1)
	assert.Equal(t, "wg1", eps[0].Tag)
}

func TestClash2singUnsupportedTypeSkipped(t *testing.T) {
	c := clash.Clash{}
	require.NoError(t, yaml.Unmarshal([]byte(`
proxies:
  - name: x
    type: unknown-proto
    server: 1.1.1.1
    port: "443"
  - name: v
    type: vmess
    server: 1.1.1.1
    port: "443"
    uuid: uuid
`), &c))

	out, _, err := Clash2sing(c, model.SINGLATEST)
	assert.Error(t, err)
	assert.Len(t, out, 1)
	assert.Equal(t, "v", out[0].Tag)
}
