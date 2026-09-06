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

// --- snell() 直测 ---

func TestSnell_V4_NoObfs(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-v4
type: snell
server: example.com
port: "2345"
psk: mypsk123456
version: 4
`)
	s, err := comm(&p)
	require.NoError(t, err)
	out, err := snell(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, 4, out[0].Version)
	assert.Equal(t, "mypsk123456", out[0].Psk)
	assert.Equal(t, "", out[0].ObfsMode)
	assert.Equal(t, "", out[0].ObfsHost)
	assert.False(t, out[0].Reuse)
	assert.Equal(t, "snell", out[0].Type)
	assert.Equal(t, "snell-v4", out[0].Tag)
	assert.Equal(t, "example.com", out[0].Server)
	assert.Equal(t, 2345, out[0].ServerPort)

	b, err := json.Marshal(out[0])
	require.NoError(t, err)
	jsonStr := string(b)
	assert.NotContains(t, jsonStr, "obfs_host")
	assert.NotContains(t, jsonStr, `"network"`)
	assert.NotContains(t, jsonStr, `"reuse"`)
}

func TestSnell_V4_HttpObfs(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-v4-http
type: snell
server: example.com
port: "2345"
psk: mypsk123456
version: 4
reuse: true
obfs-opts:
  mode: http
  host: bing.com
`)
	s, err := comm(&p)
	require.NoError(t, err)
	out, err := snell(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, 4, out[0].Version)
	assert.Equal(t, "mypsk123456", out[0].Psk)
	assert.Equal(t, "http", out[0].ObfsMode)
	assert.Equal(t, "bing.com", out[0].ObfsHost)
	assert.True(t, out[0].Reuse)

	b, err := json.Marshal(out[0])
	require.NoError(t, err)
	jsonStr := string(b)
	assert.Contains(t, jsonStr, `"psk":"mypsk123456"`)
	assert.Contains(t, jsonStr, `"obfs_mode":"http"`)
	assert.Contains(t, jsonStr, `"obfs_host":"bing.com"`)
	assert.Contains(t, jsonStr, `"reuse":true`)
}

func TestSnell_V4_HttpObfs_DefaultHost(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-v4
type: snell
server: example.com
port: "2345"
psk: psk
version: 4
obfs-opts:
  mode: http
`)
	s, err := comm(&p)
	require.NoError(t, err)
	out, err := snell(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	assert.Equal(t, "http", out[0].ObfsMode)
	assert.Equal(t, "bing.com", out[0].ObfsHost)
}

func TestSnell_V4_TlsObfs(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-v4
type: snell
server: example.com
port: "2345"
psk: psk
version: 4
obfs-opts:
  mode: tls
  host: example.com
`)
	s, err := comm(&p)
	require.NoError(t, err)
	out, err := snell(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	assert.Equal(t, "tls", out[0].ObfsMode)
	assert.Equal(t, "example.com", out[0].ObfsHost)
}

func TestSnell_V4_TlsObfs_DefaultHost(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-v4
type: snell
server: example.com
port: "2345"
psk: psk
version: 4
obfs-opts:
  mode: tls
`)
	s, err := comm(&p)
	require.NoError(t, err)
	out, err := snell(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	assert.Equal(t, "tls", out[0].ObfsMode)
	assert.Equal(t, "bing.com", out[0].ObfsHost)
}

func TestSnell_V4_ReuseFalse(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-v4
type: snell
server: example.com
port: "2345"
psk: psk
version: 4
reuse: false
`)
	s, err := comm(&p)
	require.NoError(t, err)
	out, err := snell(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	assert.False(t, out[0].Reuse)
	b, err := json.Marshal(out[0])
	require.NoError(t, err)
	assert.NotContains(t, string(b), `"reuse"`)
}

func TestSnell_V4_NoneObfsExplicit(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-v4
type: snell
server: example.com
port: "2345"
psk: psk
version: 4
obfs-opts:
  mode: none
  host: bing.com
`)
	s, err := comm(&p)
	require.NoError(t, err)
	out, err := snell(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	assert.Equal(t, "", out[0].ObfsMode)
	assert.Equal(t, "", out[0].ObfsHost)
}

func TestSnell_V5_MapsToV4(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-v5
type: snell
server: example.com
port: "2345"
psk: psk
version: 5
`)
	s, err := comm(&p)
	require.NoError(t, err)
	out, err := snell(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	assert.Equal(t, 4, out[0].Version)
}

func TestSnell_V6_Basic(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-v6
type: snell
server: example.com
port: "2345"
psk: yyy
version: 6
`)
	s, err := comm(&p)
	require.NoError(t, err)
	out, err := snell(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, 6, out[0].Version)
	assert.Equal(t, "yyy", out[0].Psk)
	assert.Equal(t, "", out[0].ObfsMode)
	assert.Equal(t, "", out[0].ObfsHost)
	assert.False(t, out[0].Reuse)
	b, err := json.Marshal(out[0])
	require.NoError(t, err)
	assert.NotContains(t, string(b), "obfs_mode")
	assert.NotContains(t, string(b), "obfs_host")
}

func TestSnell_V6_IgnoresReuseAndObfs(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-v6
type: snell
server: example.com
port: "2345"
psk: psk
version: 6
reuse: true
obfs-opts:
  mode: http
  host: bing.com
`)
	s, err := comm(&p)
	require.NoError(t, err)
	out, err := snell(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	assert.Equal(t, 6, out[0].Version)
	assert.False(t, out[0].Reuse)
	assert.Equal(t, "", out[0].ObfsMode)
	assert.Equal(t, "", out[0].ObfsHost)
}

func TestSnell_Version_AsString(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-v4
type: snell
server: example.com
port: "2345"
psk: psk
version: "4"
`)
	s, err := comm(&p)
	require.NoError(t, err)
	out, err := snell(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	assert.Equal(t, 4, out[0].Version)
}

func TestSnell_PskEmpty_Error(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-v4
type: snell
server: example.com
port: "2345"
version: 4
`)
	s, err := comm(&p)
	require.NoError(t, err)
	_, err = snell(&p, s, model.SINGLATEST)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "psk")
}

func TestSnell_PskEmptyString_Error(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-v4
type: snell
server: example.com
port: "2345"
psk: ""
version: 4
`)
	s, err := comm(&p)
	require.NoError(t, err)
	_, err = snell(&p, s, model.SINGLATEST)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "psk")
}

func TestSnell_Version1_Error(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-v1
type: snell
server: example.com
port: "2345"
psk: psk
version: 1
`)
	s, err := comm(&p)
	require.NoError(t, err)
	_, err = snell(&p, s, model.SINGLATEST)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported version")
	assert.Contains(t, err.Error(), "1")
}

func TestSnell_Version2_Error(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-v2
type: snell
server: example.com
port: "2345"
psk: psk
version: 2
`)
	s, err := comm(&p)
	require.NoError(t, err)
	_, err = snell(&p, s, model.SINGLATEST)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported version")
}

func TestSnell_Version3_Error(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-v3
type: snell
server: example.com
port: "2345"
psk: psk
version: 3
`)
	s, err := comm(&p)
	require.NoError(t, err)
	_, err = snell(&p, s, model.SINGLATEST)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported version")
}

func TestSnell_Version0_Error(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-v0
type: snell
server: example.com
port: "2345"
psk: psk
version: 0
`)
	s, err := comm(&p)
	require.NoError(t, err)
	_, err = snell(&p, s, model.SINGLATEST)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported version")
}

func TestSnell_VersionMissing_Error(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-missing
type: snell
server: example.com
port: "2345"
psk: psk
`)
	s, err := comm(&p)
	require.NoError(t, err)
	_, err = snell(&p, s, model.SINGLATEST)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported version")
}

func TestSnell_ObfsShadowTLS_Error(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-shadow
type: snell
server: example.com
port: "2345"
psk: psk
version: 4
obfs-opts:
  mode: shadow-tls
  host: bing.com
`)
	s, err := comm(&p)
	require.NoError(t, err)
	_, err = snell(&p, s, model.SINGLATEST)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
	assert.Contains(t, err.Error(), "shadow-tls")
}

func TestSnell_ObfsRestls_Error(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-restls
type: snell
server: example.com
port: "2345"
psk: psk
version: 4
obfs-opts:
  mode: restls
  host: bing.com
`)
	s, err := comm(&p)
	require.NoError(t, err)
	_, err = snell(&p, s, model.SINGLATEST)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
}

func TestSnell_ObfsJls_Error(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-jls
type: snell
server: example.com
port: "2345"
psk: psk
version: 4
obfs-opts:
  mode: jls
  host: bing.com
`)
	s, err := comm(&p)
	require.NoError(t, err)
	_, err = snell(&p, s, model.SINGLATEST)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
}

func TestSnell_ObfsInvalid_Error(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-invalid
type: snell
server: example.com
port: "2345"
psk: psk
version: 4
obfs-opts:
  mode: foo
`)
	s, err := comm(&p)
	require.NoError(t, err)
	_, err = snell(&p, s, model.SINGLATEST)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
}

func TestSnell_TfoMptcpPassthrough(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-v4
type: snell
server: example.com
port: "2345"
psk: psk
version: 4
tfo: true
mptcp: true
`)
	s, err := comm(&p)
	require.NoError(t, err)
	out, err := snell(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	assert.True(t, out[0].TcpFastOpen)
	assert.True(t, out[0].TcpMultiPath)
}

func TestSnell_SmuxPassthrough(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-v4
type: snell
server: example.com
port: "2345"
psk: psk
version: 4
smux:
  enabled: true
  max-streams: 8
`)
	s, err := comm(&p)
	require.NoError(t, err)
	out, err := snell(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	require.NotNil(t, out[0].Multiplex)
	assert.True(t, out[0].Multiplex.Enabled)
	assert.Equal(t, 8, out[0].Multiplex.MaxStreams)
}

func TestSnell_JSONSerialization(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-v4-http
type: snell
server: example.com
port: "2345"
psk: mypsk
version: 4
reuse: true
obfs-opts:
  mode: http
  host: bing.com
`)
	s, err := comm(&p)
	require.NoError(t, err)
	out, err := snell(&p, s, model.SINGLATEST)
	require.NoError(t, err)

	b, err := json.Marshal(out[0])
	require.NoError(t, err)
	jsonStr := string(b)
	assert.Contains(t, jsonStr, `"psk":"mypsk"`)
	assert.Contains(t, jsonStr, `"obfs_mode":"http"`)
	assert.Contains(t, jsonStr, `"obfs_host":"bing.com"`)
	assert.Contains(t, jsonStr, `"version":4`)
	assert.NotContains(t, jsonStr, `"network"`)
	assert.NotContains(t, jsonStr, `"tls"`)
	assert.NotContains(t, jsonStr, `"mode"`)
}

func TestSnell_JSONSerialization_V6(t *testing.T) {
	p := proxyFromYAML(t, `
name: snell-v6
type: snell
server: example.com
port: "2345"
psk: psk
version: 6
`)
	s, err := comm(&p)
	require.NoError(t, err)
	out, err := snell(&p, s, model.SINGLATEST)
	require.NoError(t, err)
	b, err := json.Marshal(out[0])
	require.NoError(t, err)
	jsonStr := string(b)
	assert.Contains(t, jsonStr, `"version":6`)
	assert.NotContains(t, jsonStr, "obfs_mode")
	assert.NotContains(t, jsonStr, "obfs_host")
	assert.NotContains(t, jsonStr, `"reuse"`)
}

// --- Clash2sing 集成 ---

func TestClash2sing_SnellMixedTypes(t *testing.T) {
	c := clash.Clash{}
	require.NoError(t, yaml.Unmarshal([]byte(`
proxies:
  - name: snell-v4
    type: snell
    server: 1.1.1.1
    port: "2345"
    psk: psk1
    version: 4
  - name: vmess1
    type: vmess
    server: 1.1.1.1
    port: "443"
    uuid: uuid
  - name: trojan1
    type: trojan
    server: 3.3.3.3
    port: "443"
    password: pass
`), &c))

	out, eps, err := Clash2sing(c, model.SINGLATEST)
	require.NoError(t, err)
	assert.Len(t, out, 3)
	assert.Empty(t, eps)
	tags := []string{out[0].Tag, out[1].Tag, out[2].Tag}
	assert.Contains(t, tags, "snell-v4")
	assert.Contains(t, tags, "vmess1")
	assert.Contains(t, tags, "trojan1")
}

func TestClash2sing_SnellUnsupportedVersionSkipped(t *testing.T) {
	c := clash.Clash{}
	require.NoError(t, yaml.Unmarshal([]byte(`
proxies:
  - name: snell-bad
    type: snell
    server: 1.1.1.1
    port: "2345"
    psk: psk
    version: 1
  - name: vmess1
    type: vmess
    server: 1.1.1.1
    port: "443"
    uuid: uuid
`), &c))

	out, _, err := Clash2sing(c, model.SINGLATEST)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported version")
	require.Len(t, out, 1)
	assert.Equal(t, "vmess1", out[0].Tag)
}

func TestClash2sing_SnellUnsupportedObfsSkipped(t *testing.T) {
	c := clash.Clash{}
	require.NoError(t, yaml.Unmarshal([]byte(`
proxies:
  - name: snell-shadow
    type: snell
    server: 1.1.1.1
    port: "2345"
    psk: psk
    version: 4
    obfs-opts:
      mode: shadow-tls
      host: bing.com
  - name: ss1
    type: ss
    server: 1.1.1.1
    port: "8388"
    password: pass
    cipher: aes-256-gcm
`), &c))

	out, _, err := Clash2sing(c, model.SINGLATEST)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "obfs mode")
	require.Len(t, out, 1)
	assert.Equal(t, "ss1", out[0].Tag)
}

func TestClash2sing_SnellPskEmptySkipped(t *testing.T) {
	c := clash.Clash{}
	require.NoError(t, yaml.Unmarshal([]byte(`
proxies:
  - name: snell-nopsk
    type: snell
    server: 1.1.1.1
    port: "2345"
    version: 4
  - name: vmess1
    type: vmess
    server: 1.1.1.1
    port: "443"
    uuid: uuid
`), &c))

	out, _, err := Clash2sing(c, model.SINGLATEST)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "psk")
	require.Len(t, out, 1)
	assert.Equal(t, "vmess1", out[0].Tag)
}

func TestClash2sing_SnellV5AndV4Coexist(t *testing.T) {
	c := clash.Clash{}
	require.NoError(t, yaml.Unmarshal([]byte(`
proxies:
  - name: snell-v5
    type: snell
    server: 1.1.1.1
    port: "2345"
    psk: psk1
    version: 5
  - name: snell-v4-http
    type: snell
    server: 2.2.2.2
    port: "2345"
    psk: psk2
    version: 4
    obfs-opts:
      mode: http
      host: bing.com
`), &c))

	out, _, err := Clash2sing(c, model.SINGLATEST)
	require.NoError(t, err)
	require.Len(t, out, 2)
	for _, o := range out {
		assert.Equal(t, 4, o.Version)
	}
}

func TestClash2sing_AllSnellFail(t *testing.T) {
	c := clash.Clash{}
	require.NoError(t, yaml.Unmarshal([]byte(`
proxies:
  - name: snell-bad1
    type: snell
    server: 1.1.1.1
    port: "2345"
    psk: psk
    version: 1
  - name: snell-bad2
    type: snell
    server: 1.1.1.1
    port: "2345"
    version: 4
`), &c))

	out, _, err := Clash2sing(c, model.SINGLATEST)
	require.Error(t, err)
	assert.Empty(t, out)
}

func TestSnell_TypeMapRegistered(t *testing.T) {
	assert.Equal(t, "snell", typeMap["snell"])
	_, ok := convertMap["snell"]
	assert.True(t, ok)
}
