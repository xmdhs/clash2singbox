package convert

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSsBase64UserInfo(t *testing.T) {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pass"))
	u := fmt.Sprintf("ss://%s@example.com:8388#node", userinfo)
	p, err := ParseURL(u)
	require.NoError(t, err)
	assert.Equal(t, "ss", p.Type)
	assert.Equal(t, "node", p.Name)
	assert.Equal(t, "example.com", p.Server)
	assert.Equal(t, "8388", p.Port)
	assert.Equal(t, "aes-256-gcm", p.Cipher)
	assert.Equal(t, "pass", p.Password)
}

func TestParseSsPlainUserInfo(t *testing.T) {
	// userinfo 形式 method:password（不是 base64）
	p, err := ParseURL("ss://aes-128-gcm:pass@example.com:8388#node")
	require.NoError(t, err)
	assert.Equal(t, "aes-128-gcm", p.Cipher)
	assert.Equal(t, "pass", p.Password)
}

func TestParseSsInvalidLink(t *testing.T) {
	// 非 base64 用户名（首字节 %21 即 "!"），且无 password 分隔 → 解析失败
	_, err := ParseURL("ss://%21@example.com:8388#node")
	assert.Error(t, err)
}

func TestParseSsObfsPlugin(t *testing.T) {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pass"))
	plugin := "obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dobfs.example.com"
	u := fmt.Sprintf("ss://%s@example.com:8388?plugin=%s#node", userinfo, plugin)
	p, err := ParseURL(u)
	require.NoError(t, err)
	assert.Equal(t, "obfs", p.Plugin)
	// PluginOpts 为 yaml.Node，经 Encode 回 map 校验
	opts := map[string]string{}
	require.NoError(t, p.PluginOpts.Decode(&opts))
	assert.Equal(t, "http", opts["mode"])
	assert.Equal(t, "obfs.example.com", opts["host"])
}

func TestParseSsV2RayPlugin(t *testing.T) {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pass"))
	plugin := "v2ray-plugin%3Bmode%3Dwebsocket%3Btls%3Bhost%3Dws.example.com%3Bpath%3D%2Fws"
	u := fmt.Sprintf("ss://%s@example.com:8388?plugin=%s#node", userinfo, plugin)
	p, err := ParseURL(u)
	require.NoError(t, err)
	assert.Equal(t, "v2ray-plugin", p.Plugin)
	opts := map[string]any{}
	require.NoError(t, p.PluginOpts.Decode(&opts))
	assert.Equal(t, "websocket", opts["mode"])
	assert.Equal(t, true, opts["tls"])
	assert.Equal(t, "ws.example.com", opts["host"])
}

func TestParseSsTfo(t *testing.T) {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pass"))
	u := fmt.Sprintf("ss://%s@example.com:8388?tfo=1#node", userinfo)
	p, err := ParseURL(u)
	require.NoError(t, err)
	assert.True(t, p.Tfo)
}

func vmessURL(payload any) string {
	b, _ := json.Marshal(payload)
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

func TestParseVmessBasic(t *testing.T) {
	u := vmessURL(map[string]any{
		"add": "1.2.3.4", "port": 443, "id": "uuid", "aid": 2, "scy": "auto",
		"net": "tcp", "tls": "", "ps": "vmess-node",
	})
	p, err := ParseURL(u)
	require.NoError(t, err)
	assert.Equal(t, "vmess", p.Type)
	assert.Equal(t, "vmess-node", p.Name)
	assert.Equal(t, "1.2.3.4", p.Server)
	assert.Equal(t, "443", p.Port)
	assert.Equal(t, "uuid", p.Uuid)
	assert.Equal(t, int(p.AlterId), 2)
	assert.Equal(t, "auto", p.Cipher)
}

func TestParseVmessPortAsString(t *testing.T) {
	u := vmessURL(map[string]any{
		"add": "example.com", "port": "8443", "id": "uuid", "net": "tcp", "ps": "n",
	})
	p, err := ParseURL(u)
	require.NoError(t, err)
	assert.Equal(t, "8443", p.Port)
}

func TestParseVmessWsTLS(t *testing.T) {
	u := vmessURL(map[string]any{
		"add": "example.com", "port": 443, "id": "uuid", "aid": 0,
		"net": "ws", "host": "ws.example.com", "path": "/ws", "tls": "tls",
		"sni": "sni.example.com", "alpn": "h2,http/1.1", "fp": "chrome", "ps": "n",
	})
	p, err := ParseURL(u)
	require.NoError(t, err)
	assert.True(t, bool(p.Tls))
	assert.Equal(t, "sni.example.com", p.Servername)
	assert.Equal(t, "ws", p.Network)
	assert.Equal(t, "/ws", p.WsOpts.Path)
	assert.Equal(t, "ws.example.com", p.WsOpts.Headers["Host"])
	assert.Equal(t, []string{"h2", "http/1.1"}, p.Alpn)
	assert.Equal(t, "chrome", p.ClientFingerprint)
}

func TestParseVmessH2(t *testing.T) {
	u := vmessURL(map[string]any{
		"add": "example.com", "port": 443, "id": "uuid",
		"net": "h2", "host": "h2.example.com", "path": "/h2", "ps": "n",
	})
	p, err := ParseURL(u)
	require.NoError(t, err)
	assert.Equal(t, "/h2", p.H2Opts.Path)
	assert.Equal(t, []string{"h2.example.com"}, p.H2Opts.Host)
}

func TestParseVmessGrpc(t *testing.T) {
	u := vmessURL(map[string]any{
		"add": "example.com", "port": 443, "id": "uuid",
		"net": "grpc", "path": "my-svc", "ps": "n",
	})
	p, err := ParseURL(u)
	require.NoError(t, err)
	assert.Equal(t, "my-svc", p.GrpcOpts.GrpcServiceName)
}

func TestParseVmessInvalidBase64(t *testing.T) {
	_, err := ParseURL("vmess://@@not-base64@@")
	assert.Error(t, err)
}

func TestParseVlessReality(t *testing.T) {
	p, err := ParseURL("vless://uuid@example.com:443?security=reality&pbk=pub-key&sid=short-id&flow=xtls-rprx-vision#node")
	require.NoError(t, err)
	assert.Equal(t, "vless", p.Type)
	assert.Equal(t, "uuid", p.Uuid)
	assert.True(t, bool(p.Tls))
	assert.Equal(t, "pub-key", p.RealityOpts.PublicKey)
	assert.Equal(t, "short-id", p.RealityOpts.ShortId)
	assert.Equal(t, "xtls-rprx-vision", p.Flow)
}

func TestParseVlessWs(t *testing.T) {
	p, err := ParseURL("vless://uuid@example.com:443?type=ws&host=ws.example.com&path=%2Fws&security=none#node")
	require.NoError(t, err)
	assert.False(t, bool(p.Tls))
	assert.Equal(t, "ws", p.Network)
	assert.Equal(t, "/ws", p.WsOpts.Path)
	assert.Equal(t, "ws.example.com", p.WsOpts.Headers["Host"])
}

func TestParseVlessGrpc(t *testing.T) {
	p, err := ParseURL("vless://uuid@example.com:443?type=grpc&path=svc&security=tls&sni=sni.example.com#node")
	require.NoError(t, err)
	assert.True(t, bool(p.Tls))
	assert.Equal(t, "grpc", p.Network)
	assert.Equal(t, "svc", p.GrpcOpts.GrpcServiceName)
	assert.Equal(t, "sni.example.com", p.Servername)
}

func TestParseVlessPeerFallback(t *testing.T) {
	p, err := ParseURL("vless://uuid@example.com:443?security=tls&peer=peer.example.com#node")
	require.NoError(t, err)
	assert.Equal(t, "peer.example.com", p.Servername)
}

func TestParseVlessAllowInsecure(t *testing.T) {
	p, err := ParseURL("vless://uuid@example.com:443?security=tls&allowinsecure=1#node")
	require.NoError(t, err)
	assert.True(t, bool(p.SkipCertVerify))
}

func TestParseTrojanWS(t *testing.T) {
	p, err := ParseURL("trojan://pass@example.com:443?type=ws&host=ws.example.com&path=%2Ftrojan-ws&sni=sni.example.com&alpn=h2%2Chttp%2F1.1&skip-cert-verify=1&fp=chrome#node")
	require.NoError(t, err)
	assert.Equal(t, "trojan", p.Type)
	assert.Equal(t, "pass", p.Password)
	assert.Equal(t, "ws", p.Network)
	assert.Equal(t, "/trojan-ws", p.WsOpts.Path)
	assert.Equal(t, "ws.example.com", p.WsOpts.Headers["Host"])
	assert.Equal(t, "sni.example.com", p.Sni)
	assert.Equal(t, []string{"h2", "http/1.1"}, p.Alpn)
	assert.True(t, bool(p.SkipCertVerify))
	assert.Equal(t, "chrome", p.ClientFingerprint)
}

func TestParseTrojanAllowInsecure(t *testing.T) {
	p, err := ParseURL("trojan://pass@example.com:443?allowInsecure=true#node")
	require.NoError(t, err)
	assert.True(t, bool(p.SkipCertVerify))
}

func TestParseHysteria(t *testing.T) {
	p, err := ParseURL("hysteria://example.com:443?auth=my-auth&obfsParam=xplus-pass&insecure=1&mport=500-505&upmbps=50&downmbps=100&fast-open=1&recv-window-conn=512&recv-window=1024&disable-mtu-discovery=1&protocol=faketcp&alpn=h3&fingerprint=chrome&sni=sni.example.com#node")
	require.NoError(t, err)
	assert.Equal(t, "hysteria", p.Type)
	assert.Equal(t, "my-auth", p.AuthStr)
	assert.Equal(t, "xplus-pass", p.Obfs)
	assert.True(t, bool(p.SkipCertVerify))
	assert.Equal(t, "500-505", p.Ports)
	assert.Equal(t, "50", p.Up)
	assert.Equal(t, "100", p.Down)
	assert.True(t, bool(p.FastOpen))
	assert.Equal(t, int(p.RecvWindowConn), 512)
	assert.Equal(t, int(p.RecvWindow), 1024)
	assert.True(t, bool(p.DisableMtuDiscovery))
	assert.Equal(t, "faketcp", p.Protocol)
	assert.Equal(t, []string{"h3"}, p.Alpn)
	assert.Equal(t, "chrome", p.Fingerprint)
	assert.Equal(t, "sni.example.com", p.Sni)
}

func TestParseHysteria2(t *testing.T) {
	p, err := ParseURL("hy2://pass@example.com:443?insecure=1&sni=sni.example.com&obfs=salamander&obfs-password=obfs-pass&mport=700-701#node")
	require.NoError(t, err)
	assert.Equal(t, "hysteria2", p.Type)
	assert.Equal(t, "pass", p.Password)
	assert.True(t, bool(p.SkipCertVerify))
	assert.Equal(t, "sni.example.com", p.Sni)
	assert.Equal(t, "salamander", p.Obfs)
	assert.Equal(t, "obfs-pass", p.ObfsPassword)
	assert.Equal(t, "700-701", p.Ports)
}

func TestParseTuic(t *testing.T) {
	p, err := ParseURL("tuic://user-uuid:secret@example.com:443?sni=sni.example.com&alpn=h3&skip-cert-verify=1&disable-sni=1&congestion-controller=bbr&udp-relay-mode=native&reduce-rtt=1&heartbeat-interval=10000&udp-over-stream=1&udp-over-stream-version=2#node")
	require.NoError(t, err)
	assert.Equal(t, "tuic", p.Type)
	assert.Equal(t, "user-uuid", p.Uuid)
	assert.Equal(t, "secret", p.Password)
	assert.Equal(t, "sni.example.com", p.Sni)
	assert.Equal(t, []string{"h3"}, p.Alpn)
	assert.True(t, bool(p.SkipCertVerify))
	assert.True(t, bool(p.DisableSni))
	assert.Equal(t, "bbr", p.CongestionController)
	assert.Equal(t, "native", p.UdpRelayMode)
	assert.True(t, bool(p.ReduceRtt))
	assert.Equal(t, int(p.HeartbeatInterval), 10000)
	assert.True(t, bool(p.UdpOverStream))
	assert.Equal(t, int(p.UdpOverStreamVersion), 2)
}

func TestParseSocks5(t *testing.T) {
	p, err := ParseURL("socks5://user:pass@example.com:1080#node")
	require.NoError(t, err)
	assert.Equal(t, "socks5", p.Type)
	assert.Equal(t, "user", p.Username)
	assert.Equal(t, "pass", p.Password)
	assert.Equal(t, "1080", p.Port)
}

func TestParseHttp(t *testing.T) {
	p, err := ParseURL("http://user:pass@example.com:8080#node")
	require.NoError(t, err)
	assert.Equal(t, "http", p.Type)
	assert.Equal(t, "user", p.Username)
	assert.Equal(t, "pass", p.Password)
}

func TestParseHttpsSetsTLS(t *testing.T) {
	p, err := ParseURL("https://example.com:8443#node")
	require.NoError(t, err)
	assert.Equal(t, "http", p.Type)
	assert.True(t, bool(p.Tls))
}

func TestParseAnytls(t *testing.T) {
	p, err := ParseURL("anytls://pass@example.com:443?sni=sni.example.com&insecure=1#node")
	require.NoError(t, err)
	assert.Equal(t, "anytls", p.Type)
	assert.Equal(t, "pass", p.Password)
	assert.Equal(t, "sni.example.com", p.Servername)
	assert.True(t, bool(p.SkipCertVerify))
}

func TestParseURLUnsupportedScheme(t *testing.T) {
	_, err := ParseURL("weird://x@example.com:443#node")
	assert.Error(t, err)
}

func TestParseURLMalformed(t *testing.T) {
	_, err := ParseURL("://:")
	assert.Error(t, err)
}
