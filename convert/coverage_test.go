package convert

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmdhs/clash2singbox/model"
	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
	"gopkg.in/yaml.v3"
)

// --- Clash2sing / comm error 与分支 ---

func TestClash2singWireguardError(t *testing.T) {
	c := clash.Clash{}
	require.NoError(t, yaml.Unmarshal([]byte(`
proxies:
  - name: badwg
    type: wireguard
    server: example.com
    port: "51820"
    private-key: priv
    ip: not-an-ip
  - name: good
    type: vmess
    server: 1.2.3.4
    port: "443"
    uuid: u
`), &c))
	out, _, err := Clash2sing(c, model.SINGLATEST)
	assert.Error(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, "good", out[0].Tag)
}

func TestClash2singInvalidPort(t *testing.T) {
	c := clash.Clash{}
	require.NoError(t, yaml.Unmarshal([]byte(`
proxies:
  - name: bad
    type: vmess
    server: example.com
    port: "not-a-port"
    uuid: u
`), &c))
	_, _, err := Clash2sing(c, model.SINGLATEST)
	assert.Error(t, err)
}

func TestClash2singConvertError(t *testing.T) {
	// vless 不支持的 flow 会导致转换报错
	c := clash.Clash{}
	require.NoError(t, yaml.Unmarshal([]byte(`
proxies:
  - name: bad
    type: vless
    server: example.com
    port: "443"
    uuid: u
    flow: xtls-rprx-direct
`), &c))
	_, _, err := Clash2sing(c, model.SINGLATEST)
	assert.Error(t, err)
}

func TestClash2singNonRelayGroup(t *testing.T) {
	c := clash.Clash{}
	require.NoError(t, yaml.Unmarshal([]byte(`
proxies:
  - name: n1
    type: vmess
    server: 1.1.1.1
    port: "443"
    uuid: u
proxy-groups:
  - name: sel
    type: select
    proxies: [n1]
`), &c))
	out, _, err := Clash2sing(c, model.SINGLATEST)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, "n1", out[0].Tag)
}

func TestCommSmuxZeroMaxStreams(t *testing.T) {
	p := proxyFromYAML(t, `
name: v
type: vmess
server: example.com
port: "443"
smux:
  enabled: true
  max-streams: 0
  min-streams: 8
  max-connections: 8
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	require.NotNil(t, s.Multiplex)
	assert.Equal(t, 8, s.Multiplex.MinStreams)
	assert.Equal(t, 8, s.Multiplex.MaxConnections)
	// 未过滤任何 thing，max-streams 保持 0
	assert.Equal(t, 0, s.Multiplex.MaxStreams)
}

// --- hysteria 分支 ---

func TestHysteriaNoPortError(t *testing.T) {
	p := &clash.Proxies{Type: "hysteria", Name: "h", Server: "x", Up: "1", Down: "1"}
	s := &singbox.SingBoxOut{}
	err := hysteria(p, s)
	assert.ErrorIs(t, err, ErrNotSupportType)
}

func TestHysteriaPortsError(t *testing.T) {
	p := &clash.Proxies{Type: "hysteria", Name: "h", Server: "x", Ports: "123-x", Up: "1", Down: "1"}
	s := &singbox.SingBoxOut{}
	assert.Error(t, hysteria(p, s))
}

func TestHysteriaCaStr1(t *testing.T) {
	p := &clash.Proxies{Type: "hysteria", Name: "h", Server: "x", Port: "443", Up: "1", Down: "1", CaStr1: "PEM1"}
	s := &singbox.SingBoxOut{}
	require.NoError(t, hysteria(p, s))
	assert.Equal(t, []string{"PEM1"}, s.TLS.Certificate)
}

func TestHysteia2PortsErrorLatest(t *testing.T) {
	p := &clash.Proxies{Type: "hysteria2", Name: "h", Server: "x", Ports: "123-x", Up: "1", Down: "1"}
	s := &singbox.SingBoxOut{}
	_, err := hysteia2(p, s, model.SINGLATEST)
	assert.Error(t, err)
}

func TestHysteia2PortsError110(t *testing.T) {
	p := &clash.Proxies{Type: "hysteria2", Name: "h", Server: "x", Ports: "123-x", Up: "1", Down: "1"}
	s := &singbox.SingBoxOut{}
	_, err := hysteia2(p, s, model.SING110)
	assert.Error(t, err)
}

func TestHysteia2UpDownError(t *testing.T) {
	p := &clash.Proxies{Type: "hysteria2", Name: "h", Server: "x", Port: "443", Up: "invalid", Down: "invalid"}
	s := &singbox.SingBoxOut{}
	_, err := hysteia2(p, s, model.SINGLATEST)
	assert.Error(t, err)
}

func TestAnyToMbpsT(t *testing.T) {
	v, err := anyToMbps("1Tbps")
	require.NoError(t, err)
	assert.Equal(t, 1000*1000, v)
}

func TestPortsToPortErrors(t *testing.T) {
	// endPort 非法
	_, err := portsToPort("100-x")
	assert.Error(t, err)
	// startPort 非法
	_, err = portsToPort("x-100")
	assert.Error(t, err)
	// 区间倒置
	_, err = portsToPort("200-100")
	assert.ErrorIs(t, err, ErrNotSupportType)
	// 单端口非法
	_, err = portsToPort("abc")
	assert.Error(t, err)
}

func TestPortsToPortsErrors(t *testing.T) {
	_, err := portsToPorts("100-x")
	assert.Error(t, err)
	_, err = portsToPorts("x-100")
	assert.Error(t, err)
	_, err = portsToPorts("200-100")
	assert.ErrorIs(t, err, ErrNotSupportType)
	got, err := portsToPorts("443")
	require.NoError(t, err)
	assert.Equal(t, []string{"443:443"}, got)
}

// --- ss 分支 ---

func TestSsPluginDecodeErrors(t *testing.T) {
	// shadow-tls 插件 opts 无法解码
	p := clash.Proxies{Plugin: "shadow-tls"}
	require.NoError(t, yaml.Unmarshal([]byte("plugin-opts: just-a-string\n"), &p))
	_, err := ss(&p, &singbox.SingBoxOut{}, model.SINGLATEST)
	assert.Error(t, err)

	// v2ray-plugin 解码失败
	p2 := clash.Proxies{Plugin: "v2ray-plugin"}
	require.NoError(t, yaml.Unmarshal([]byte("plugin-opts: just-a-string\n"), &p2))
	assert.Error(t, ssPlugin(p2.PluginOpts, &singbox.SingBoxOut{}, "v2ray-plugin"))

	// obfs 解码失败
	p3 := clash.Proxies{Plugin: "obfs"}
	require.NoError(t, yaml.Unmarshal([]byte("plugin-opts: just-a-string\n"), &p3))
	assert.Error(t, ssPlugin(p3.PluginOpts, &singbox.SingBoxOut{}, "obfs"))
}

func TestSsUnsupportedPlugin(t *testing.T) {
	p := clash.Proxies{Plugin: "weird"}
	s := &singbox.SingBoxOut{}
	err := ssPlugin(p.PluginOpts, s, "weird")
	assert.ErrorIs(t, err, ErrNotSupportPlugin)
}

func TestSsShadowTlsClientFingerprint(t *testing.T) {
	p := proxyFromYAML(t, `
name: ss
type: ss
server: example.com
port: "443"
cipher: aes-256-gcm
password: pass
client-fingerprint: chrome
plugin: shadow-tls
plugin-opts:
  host: stls.example.com
  password: sp
  version: 3
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	out, err := ss(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	require.Len(t, out, 2)
	require.NotNil(t, out[1].TLS.Utls)
	assert.Equal(t, "chrome", out[1].TLS.Utls.Fingerprint)
}

// --- url 解析补充 ---

func TestParseHysteriaObfsQuery(t *testing.T) {
	p, err := ParseURL("hysteria://example.com:443?auth=a&obfs=xplus-obfs#node")
	require.NoError(t, err)
	assert.Equal(t, "xplus-obfs", p.Obfs)
}

func TestParseTrojanFpParam(t *testing.T) {
	p, err := ParseURL("trojan://pass@example.com:443?fp=firefox#node")
	require.NoError(t, err)
	assert.Equal(t, "firefox", p.ClientFingerprint)
}

func TestParseTrojanAllowInsecureTrue(t *testing.T) {
	p, err := ParseURL("trojan://pass@example.com:443?allowInsecure=1#node")
	require.NoError(t, err)
	assert.True(t, bool(p.SkipCertVerify))
}

func TestParseVlessWsHttpUpgrade(t *testing.T) {
	p, err := ParseURL("vless://uuid@example.com:443?type=ws&path=%2Fws&headerType=http&security=none#node")
	require.NoError(t, err)
	assert.True(t, bool(p.WsOpts.V2rayHttpUpgrade))
}

func TestParseVlessH2(t *testing.T) {
	p, err := ParseURL("vless://uuid@example.com:443?type=h2&host=h2.example.com&path=%2Fh2&security=none#node")
	require.NoError(t, err)
	assert.Equal(t, "/h2", p.H2Opts.Path)
	assert.Equal(t, []string{"h2.example.com"}, p.H2Opts.Host)
}

func TestParseVlessHTTPWithObfsParamFallback(t *testing.T) {
	// host 为空时回退 obfsparam；且 tls 下用 ws Host 做 servername 兜底
	p, err := ParseURL("vless://uuid@example.com:443?type=ws&path=%2Fws&obfsparam=hs.example.com&security=tls#node")
	require.NoError(t, err)
	assert.Equal(t, "hs.example.com", p.WsOpts.Headers["Host"])
	assert.Equal(t, "hs.example.com", p.Servername)
}

func TestParseVlessHTTPHostFallback(t *testing.T) {
	p, err := ParseURL("vless://uuid@example.com:443?type=http&path=%2Fpro&host=pro.example.com&security=tls#node")
	require.NoError(t, err)
	assert.Equal(t, "/pro", p.HTTPOpts.Path[0])
	assert.Equal(t, "pro.example.com", p.Servername)
}

func TestParseVmessAidString(t *testing.T) {
	u := vmessURL(map[string]any{"add": "x", "port": 443, "id": "u", "aid": "5", "ps": "n"})
	p, err := ParseURL(u)
	require.NoError(t, err)
	assert.Equal(t, int(p.AlterId), 5)
}

func TestParseVmessHTTPTransport(t *testing.T) {
	u := vmessURL(map[string]any{"add": "example.com", "port": 80, "id": "u", "net": "http", "host": "h.example.com", "path": "/pro", "ps": "n"})
	p, err := ParseURL(u)
	require.NoError(t, err)
	assert.Equal(t, "/pro", p.HTTPOpts.Path[0])
	assert.Equal(t, "h.example.com", p.HTTPOpts.Headers["Host"][0])
}

func TestParseVmessInvalidJSON(t *testing.T) {
	u := "vmess://" + base64.StdEncoding.EncodeToString([]byte(`^not-json`))
	_, err := ParseURL(u)
	assert.Error(t, err)
}

func TestParseSsMalformedPluginValue(t *testing.T) {
	// %FF 是合法十六进制转义，解码出单字节；无分隔符 → 视为非法插件
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pass"))
	_, err := ParseURL("ss://" + userinfo + "@example.com:8388?plugin=%FF#node")
	assert.Error(t, err)
}

func TestParseSsPluginNoArg(t *testing.T) {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pass"))
	_, err := ParseURL("ss://" + userinfo + "@example.com:8388?plugin=obfs-local#node")
	assert.Error(t, err)
}

// --- vmess transport 分支 ---

func TestVmessHttpUpgradeHostFromHeader(t *testing.T) {
	p := proxyFromYAML(t, `
name: v
type: vmess
server: example.com
port: "443"
uuid: u
ws-opts:
  path: /up
  v2ray-http-upgrade: true
  headers:
    Host: hs.example.com
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	require.NoError(t, vmess(&p, s))
	assert.Equal(t, "hs.example.com", s.Transport.Host)
}

func TestVmessHTTPHostHeader(t *testing.T) {
	p := proxyFromYAML(t, `
name: v
type: vmess
server: example.com
port: "443"
uuid: u
http-opts:
  method: PUT
  path:
    - /pro
  headers:
    Host:
      - host.example.com
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	require.NoError(t, vmess(&p, s))
	assert.Equal(t, "http", s.Transport.Type)
	assert.Equal(t, []string{"host.example.com"}, s.Transport.Host)
	assert.Equal(t, "/pro", s.Transport.Path)
	assert.Equal(t, "PUT", s.Transport.Method)
}

// --- wireguard 分支 ---

func TestWireguardEndpointInvalidIP(t *testing.T) {
	p := clash.Proxies{Type: "wireguard", Name: "w", Server: "x", Port: "51820", IP: "not-an-ip"}
	_, err := wireguardEndpoint(&p)
	assert.Error(t, err)
}

func TestWireguardEndpointInvalidPort(t *testing.T) {
	p := clash.Proxies{Type: "wireguard", Name: "w", Server: "x", Port: "not-port", IP: "10.0.0.1"}
	_, err := wireguardEndpoint(&p)
	assert.Error(t, err)
}

// --- applyFilter 全分支 ---

func TestApplyFilterAllBranches(t *testing.T) {
	all := []string{"HK-01", "HK-02", "JP", "SG-01"}

	assert.Equal(t, all, applyFilter("not-a-map", all))
	assert.Equal(t, all, applyFilter(map[string]any{"type": "urltest"}, all))
	assert.Equal(t, all, applyFilter(map[string]any{"filter": "not-slice"}, all))
	// 非 map 规则、缺 acton/keywords、类型不符的规则被忽略
	assert.Equal(t, all, applyFilter(map[string]any{"filter": []any{"str"}}, all))
	assert.Equal(t, all, applyFilter(map[string]any{"filter": []any{map[string]any{"keywords": "HK"}}}, all))
	assert.Equal(t, all, applyFilter(map[string]any{"filter": []any{map[string]any{"action": 1, "keywords": "HK"}}}, all))
	assert.Equal(t, all, applyFilter(map[string]any{"filter": []any{map[string]any{"action": "include", "keywords": 7}}}, all))

	// include
	assert.Equal(t, []string{"HK-01", "HK-02"}, applyFilter(
		map[string]any{"filter": []any{map[string]any{"action": "include", "keywords": "HK"}}}, all))
	// exclude
	assert.Equal(t, []string{"JP", "SG-01"}, applyFilter(
		map[string]any{"filter": []any{map[string]any{"action": "exclude", "keywords": "HK"}}}, all))
	// 多规则串联
	assert.Equal(t, []string{"HK-01"}, applyFilter(
		map[string]any{"filter": []any{
			map[string]any{"action": "include", "keywords": "HK"},
			map[string]any{"action": "exclude", "keywords": "02"},
		}}, all))
	// include 无匹配
	assert.Equal(t, []string{}, applyFilter(
		map[string]any{"filter": []any{map[string]any{"action": "include", "keywords": "XX"}}}, all))
	// 含反斜杠的关键词原样构建（可能非法正则会 continue）
	assert.Equal(t, all, applyFilter(
		map[string]any{"filter": []any{map[string]any{"action": "include", "keywords": `?\`}}}, all))
}

func TestRemoveFilterFieldNonMap(t *testing.T) {
	assert.Equal(t, "str", removeFilterField("str"))
}

// --- PatchMap / patchMap 补充 ---

func TestPatchMapExported(t *testing.T) {
	s := []singbox.SingBoxOut{{Type: "vmess", Tag: "n1"}}
	d, err := PatchMap([]byte(`{}`), s, nil, "", "", nil, nil, true, true)
	require.NoError(t, err)
	out := d["outbounds"].([]any)
	tags := map[string]bool{}
	for _, item := range out {
		tags[itemTag(item)] = true
	}
	assert.True(t, tags["select"])
	assert.True(t, tags["urltest"])
	assert.True(t, tags["direct"])
	assert.True(t, tags["block"])
	assert.True(t, tags["dns-out"])
	assert.True(t, tags["n1"])
}

func TestPatchMapExportedNoFields(t *testing.T) {
	s := []singbox.SingBoxOut{{Type: "vmess", Tag: "n1"}}
	d, err := PatchMap([]byte(`{}`), s, nil, "", "", nil, nil, false, false)
	require.NoError(t, err)
	out := d["outbounds"].([]any)
	assert.Len(t, out, 2) // n1 + direct
}

func TestPatchMapStringAll(t *testing.T) {
	tpl := `{"outbounds":[{"type":"urltest","tag":"auto","outbounds":"{all}","filter":[{"action":"include","keywords":"HK"}]}]}`
	s := []singbox.SingBoxOut{{Type: "vmess", Tag: "HK-01"}, {Type: "vmess", Tag: "JP-01"}}
	d, err := patchMap([]byte(tpl), s, nil, "", "", nil, nil, true, false)
	require.NoError(t, err)
	out := d["outbounds"].([]any)
	auto := firstByTag(out, "auto")
	assert.Equal(t, []any{"HK-01"}, itemOutbounds(auto))
}

func TestPatchMapArrayAllWithTemplateUrltestFilter(t *testing.T) {
	tpl := `{
  "outbounds": [
    {"type":"urltest","tag":"auto","outbounds":["{all}"],"filter":[{"action":"include","keywords":"HK"}]},
    {"type":"selector","tag":"gate","outbounds":["auto","{all}"]}
  ]
}`
	s := []singbox.SingBoxOut{{Type: "vmess", Tag: "HK-01"}, {Type: "vmess", Tag: "JP-01"}}
	d, err := patchMap([]byte(tpl), s, nil, "", "", nil, nil, true, false)
	require.NoError(t, err)
	out := d["outbounds"].([]any)
	// auto 的 outbounds 被 filter 到 HK-01
	assert.Equal(t, []any{"HK-01"}, itemOutbounds(firstByTag(out, "auto")))
	// gate 含自动节点及对应节点
	gateOb := itemOutbounds(firstByTag(out, "gate"))
	assert.Contains(t, gateOb, "auto")
	assert.Contains(t, gateOb, "HK-01")
	assert.Contains(t, gateOb, "JP-01")
}

func TestPatchMapEndpoints(t *testing.T) {
	eps := []*singbox.SingBoxEndpoint{{
		Type: "wireguard", Tag: "wg", Address: []string{"10.0.0.1/32"}, PrivateKey: "priv",
	}}
	// 模板已有 endpoints 时应合并
	tpl := `{"endpoints":[{"type":"block","tag":"blk"}]}`
	d, err := patchMap([]byte(tpl), nil, eps, "", "", nil, nil, true, false)
	require.NoError(t, err)
	endpoints := d["endpoints"].([]any)
	require.Len(t, endpoints, 2)
	// 空模板也应写入
	d2, err := patchMap([]byte(`{}`), nil, eps, "", "", nil, nil, false, false)
	require.NoError(t, err)
	assert.Len(t, d2["endpoints"].([]any), 1)
}

func TestPatchMapFilterError(t *testing.T) {
	s := []singbox.SingBoxOut{{Type: "vmess", Tag: "n1"}}
	_, err := patchMap([]byte(`{}`), s, nil, "[", "", nil, nil, true, false)
	assert.Error(t, err)
	_, err = patchMap([]byte(`{}`), s, nil, "", "[", nil, nil, true, false)
	assert.Error(t, err)
}

func TestPatchInvalidTemplate(t *testing.T) {
	s := []singbox.SingBoxOut{{Type: "vmess", Tag: "n1"}}
	_, err := Patch([]byte(`{`), s, nil, "", "", nil)
	assert.Error(t, err)
	_, err = PatchMap([]byte(`{`), s, nil, "", "", nil, nil, true, true)
	assert.Error(t, err)
}

// --- 其余边缘分支补充 ---

func TestHysteia2DownErrorOnly(t *testing.T) {
	p := &clash.Proxies{Type: "hysteria2", Name: "h", Server: "x", Port: "443", Up: "1", Down: "invalid"}
	_, err := hysteia2(p, &singbox.SingBoxOut{}, model.SINGLATEST)
	assert.Error(t, err)
}

func TestPortsToPortSingle(t *testing.T) {
	got, err := portsToPort("443")
	require.NoError(t, err)
	assert.Equal(t, 443, got)
}

func TestSsViaSSPluginError(t *testing.T) {
	p := clash.Proxies{Type: "ss", Plugin: "weird"}
	_, err := ss(&p, &singbox.SingBoxOut{}, model.SINGLATEST)
	assert.Error(t, err)
}

func TestParseTrojanFingerprintParam(t *testing.T) {
	p, err := ParseURL("trojan://pass@example.com:443?fingerprint=firefox#node")
	require.NoError(t, err)
	assert.Equal(t, "firefox", p.ClientFingerprint)
}

func TestParseTrojanClientFingerprintParam(t *testing.T) {
	p, err := ParseURL("trojan://pass@example.com:443?client-fingerprint=safari#node")
	require.NoError(t, err)
	assert.Equal(t, "safari", p.ClientFingerprint)
}

func TestParseVlessAlpn(t *testing.T) {
	p, err := ParseURL("vless://uuid@example.com:443?security=none&alpn=h2,http/1.1#node")
	require.NoError(t, err)
	assert.Equal(t, []string{"h2", "http/1.1"}, p.Alpn)
}

func TestVmessWsHeadersPriority(t *testing.T) {
	p := proxyFromYAML(t, `
name: v
type: vmess
server: example.com
port: "443"
uuid: u
network: ws
ws-opts:
  path: /ws
  headers:
    Host: from-wsopts
ws-headers:
  Host: from-wshead
  X-Test: v1
`)
	s, _, err := comm(&p)
	require.NoError(t, err)
	require.NoError(t, vmess(&p, s))
	assert.Equal(t, map[string][]string{"Host": {"from-wshead"}, "X-Test": {"v1"}}, s.Transport.Headers)
}

func TestPatchMapExportedFilterError(t *testing.T) {
	s := []singbox.SingBoxOut{{Type: "vmess", Tag: "n1"}}
	_, err := PatchMap([]byte(`{}`), s, nil, "[", "", nil, nil, true, true)
	assert.Error(t, err)
	_, err = PatchMap([]byte(`{}`), s, nil, "", "[", nil, nil, true, true)
	assert.Error(t, err)
}

func TestPatchMapExportedEndpoints(t *testing.T) {
	eps := []*singbox.SingBoxEndpoint{{Type: "wireguard", Tag: "wg"}}
	d, err := PatchMap([]byte(`{}`), nil, eps, "", "", nil, nil, false, false)
	require.NoError(t, err)
	assert.Len(t, d["endpoints"].([]any), 1)

	// 模板已含 endpoints 时应合并
	d2, err := PatchMap([]byte(`{"endpoints":[{"type":"block","tag":"blk"}]}`), nil, eps, "", "", nil, nil, false, false)
	require.NoError(t, err)
	eps2 := d2["endpoints"].([]any)
	require.Len(t, eps2, 2)
	assert.Equal(t, "blk", eps2[0].(map[string]any)["tag"])
}
