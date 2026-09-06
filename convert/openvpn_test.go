package convert

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmdhs/clash2singbox/model"
	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
	"gopkg.in/yaml.v3"
)

// --- openvpnEndpoint 细粒度 ---

func TestOpenVPNEndpointMinimalCertAuth(t *testing.T) {
	p := proxyFromYAML(t, `
name: ovpn-min
type: openvpn
server: vpn.example.com
port: "1194"
ca: |
  -----BEGIN CERTIFICATE-----
  MIIB
  -----END CERTIFICATE-----
cert: |
  -----BEGIN CERTIFICATE-----
  MIIB client
  -----END CERTIFICATE-----
key: |
  -----BEGIN PRIVATE KEY-----
  MIIE
  -----END PRIVATE KEY-----
`)
	ep, err := openvpnEndpoint(&p)
	require.NoError(t, err)
	assert.Equal(t, "openvpn-client", ep.Type)
	assert.Equal(t, "ovpn-min", ep.Tag)
	assert.Equal(t, "tls", ep.Mode)
	assert.Equal(t, "vpn.example.com", ep.Server)
	assert.Equal(t, 1194, ep.ServerPort)
	assert.Equal(t, "udp", ep.Network)
	require.NotNil(t, ep.TLS)
	assert.Equal(t, []string{"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"}, ep.TLS.Certificate)
	assert.Equal(t, []string{"-----BEGIN CERTIFICATE-----\nMIIB client\n-----END CERTIFICATE-----\n"}, ep.TLS.ClientCertificate)
	assert.Equal(t, []string{"-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"}, ep.TLS.ClientKey)
	assert.Nil(t, ep.TLS.ControlWrap)
	assert.Empty(t, ep.DataCiphers)
	assert.Empty(t, ep.PingInterval)
}

func TestOpenVPNEndpointUserPassAuth(t *testing.T) {
	p := proxyFromYAML(t, `
name: ovpn-up
type: openvpn
server: vpn.example.com
port: "1194"
ca: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
username: user1
password: pass1
`)
	ep, err := openvpnEndpoint(&p)
	require.NoError(t, err)
	assert.Equal(t, "user1", ep.Username)
	assert.Equal(t, "pass1", ep.Password)
	require.NotNil(t, ep.TLS)
	assert.Empty(t, ep.TLS.ClientCertificate)
	assert.Empty(t, ep.TLS.ClientKey)
}

func TestOpenVPNEndpointCertKeyMismatch(t *testing.T) {
	p := proxyFromYAML(t, `
name: ovpn-bad
type: openvpn
server: vpn.example.com
port: "1194"
ca: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
cert: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
`)
	_, err := openvpnEndpoint(&p)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cert and key")
}

func TestOpenVPNEndpointNoAuthFails(t *testing.T) {
	p := proxyFromYAML(t, `
name: ovpn-noauth
type: openvpn
server: vpn.example.com
port: "1194"
ca: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
`)
	_, err := openvpnEndpoint(&p)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "either cert+key or username")
}

func TestOpenVPNEndpointProtoNormalize(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "udp"},
		{"udp", "udp"},
		{"udp4", "udp"},
		{"tcp", "tcp"},
		{"tcp-client", "tcp"},
		{"tcp4", "tcp"},
		{"tcp4-client", "tcp"},
		{"UDP", "udp"},
		{"TCP", "tcp"},
	}
	for _, tt := range tests {
		p := proxyFromYAML(t, `
name: ovpn
type: openvpn
server: vpn.example.com
port: "1194"
ca: "ca"
username: u
`+func() string {
			if tt.input == "" {
				return ""
			}
			return "proto: " + tt.input
		}())
		ep, err := openvpnEndpoint(&p)
		require.NoError(t, err, "proto=%q", tt.input)
		assert.Equal(t, tt.want, ep.Network, "proto=%q", tt.input)
	}
}

func TestOpenVPNEndpointDataCiphers(t *testing.T) {
	// explicit data-ciphers passthrough
	p := proxyFromYAML(t, `
name: ovpn
type: openvpn
server: vpn.example.com
port: "1194"
ca: "ca"
username: u
data-ciphers: [AES-256-GCM, AES-128-GCM]
data-ciphers-fallback: AES-128-CBC
`)
	ep, err := openvpnEndpoint(&p)
	require.NoError(t, err)
	assert.Equal(t, []string{"AES-256-GCM", "AES-128-GCM"}, ep.DataCiphers)
	assert.Equal(t, "AES-128-CBC", ep.DataCiphersFallback)

	// cipher fallback when data-ciphers empty and cipher non-default
	p2 := proxyFromYAML(t, `
name: ovpn
type: openvpn
server: vpn.example.com
port: "1194"
ca: "ca"
username: u
cipher: AES-256-GCM
`)
	ep2, err := openvpnEndpoint(&p2)
	require.NoError(t, err)
	assert.Equal(t, []string{"AES-256-GCM"}, ep2.DataCiphers)

	// default cipher should not populate DataCiphers
	p3 := proxyFromYAML(t, `
name: ovpn
type: openvpn
server: vpn.example.com
port: "1194"
ca: "ca"
username: u
cipher: AES-128-GCM
`)
	ep3, err := openvpnEndpoint(&p3)
	require.NoError(t, err)
	assert.Empty(t, ep3.DataCiphers)

	// empty cipher should not populate
	p4 := proxyFromYAML(t, `
name: ovpn
type: openvpn
server: vpn.example.com
port: "1194"
ca: "ca"
username: u
`)
	ep4, err := openvpnEndpoint(&p4)
	require.NoError(t, err)
	assert.Empty(t, ep4.DataCiphers)

	// AES-CBC normalizes to AES-128-CBC
	p5 := proxyFromYAML(t, `
name: ovpn
type: openvpn
server: vpn.example.com
port: "1194"
ca: "ca"
username: u
cipher: AES-CBC
`)
	ep5, err := openvpnEndpoint(&p5)
	require.NoError(t, err)
	assert.Equal(t, []string{"AES-128-CBC"}, ep5.DataCiphers)
}

func TestOpenVPNEndpointControlWrapTLSAuthDirection(t *testing.T) {
	for _, tc := range []struct {
		dir     string
		wantDir string
	}{
		{"0", "client"},
		{"1", "server"},
		{"", ""},
	} {
		yamlStr := `
name: ovpn
type: openvpn
server: vpn.example.com
port: "1194"
ca: "ca"
username: u
tls-auth: "-----BEGIN OpenVPN Static key V1-----\nabc\n-----END OpenVPN Static key V1-----"
`
		if tc.dir != "" {
			yamlStr += "key-direction: \"" + tc.dir + "\"\n"
		}
		p := proxyFromYAML(t, yamlStr)
		ep, err := openvpnEndpoint(&p)
		require.NoError(t, err, "dir=%q", tc.dir)
		require.NotNil(t, ep.TLS.ControlWrap)
		assert.Equal(t, "tls_auth", ep.TLS.ControlWrap.Type)
		assert.Equal(t, tc.wantDir, ep.TLS.ControlWrap.Direction)
	}
}

func TestOpenVPNEndpointControlWrapTLSCrypt(t *testing.T) {
	p := proxyFromYAML(t, `
name: ovpn
type: openvpn
server: vpn.example.com
port: "1194"
ca: "ca"
username: u
tls-crypt: "-----BEGIN OpenVPN Static key V1-----\nabc\n-----END OpenVPN Static key V1-----"
`)
	ep, err := openvpnEndpoint(&p)
	require.NoError(t, err)
	require.NotNil(t, ep.TLS.ControlWrap)
	assert.Equal(t, "tls_crypt", ep.TLS.ControlWrap.Type)
	assert.Empty(t, ep.TLS.ControlWrap.Direction)
}

func TestOpenVPNEndpointControlWrapTLSCryptV2(t *testing.T) {
	p := proxyFromYAML(t, `
name: ovpn
type: openvpn
server: vpn.example.com
port: "1194"
ca: "ca"
username: u
tls-crypt-v2: "-----BEGIN OpenVPN tls-crypt-v2 client key-----\nabc\n-----END OpenVPN tls-crypt-v2 client key-----"
`)
	ep, err := openvpnEndpoint(&p)
	require.NoError(t, err)
	require.NotNil(t, ep.TLS.ControlWrap)
	assert.Equal(t, "tls_crypt_v2", ep.TLS.ControlWrap.Type)
}

func TestOpenVPNEndpointCompLZO(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"yes", "yes"},
		{"adaptive", "yes"},
		{"YES", "yes"},
		{"no", ""},
		{"", ""},
	}
	for _, tt := range tests {
		yamlStr := `
name: ovpn
type: openvpn
server: vpn.example.com
port: "1194"
ca: "ca"
username: u
`
		if tt.input != "" {
			yamlStr += "comp-lzo: \"" + tt.input + "\"\n"
		}
		p := proxyFromYAML(t, yamlStr)
		ep, err := openvpnEndpoint(&p)
		require.NoError(t, err, "input=%q", tt.input)
		assert.Equal(t, tt.want, ep.CompressionLZO, "input=%q", tt.input)
	}
}

func TestOpenVPNEndpointPingMTUDetour(t *testing.T) {
	p := proxyFromYAML(t, `
name: ovpn
type: openvpn
server: vpn.example.com
port: "1194"
ca: "ca"
username: u
ping: 10
ping-restart: 60
mtu: 1500
dialer-proxy: ss1
`)
	ep, err := openvpnEndpoint(&p)
	require.NoError(t, err)
	assert.Equal(t, "10s", ep.PingInterval)
	assert.Equal(t, "60s", ep.PingRestart)
	assert.Equal(t, uint32(1500), ep.MTU)
	assert.Equal(t, "ss1", ep.Detour)
}

func TestOpenVPNEndpointPingZeroNotSerialized(t *testing.T) {
	p := proxyFromYAML(t, `
name: ovpn
type: openvpn
server: vpn.example.com
port: "1194"
ca: "ca"
username: u
`)
	ep, err := openvpnEndpoint(&p)
	require.NoError(t, err)
	assert.Empty(t, ep.PingInterval)
	assert.Empty(t, ep.PingRestart)
	b, err := json.Marshal(ep)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "ping_interval")
	assert.NotContains(t, string(b), "ping_restart")
}

func TestOpenVPNEndpointAuthPassthrough(t *testing.T) {
	p := proxyFromYAML(t, `
name: ovpn
type: openvpn
server: vpn.example.com
port: "1194"
ca: "ca"
username: u
auth: SHA512
`)
	ep, err := openvpnEndpoint(&p)
	require.NoError(t, err)
	assert.Equal(t, "SHA512", ep.Auth)
}

func TestOpenVPNEndpointErrors(t *testing.T) {
	// missing ca
	p := proxyFromYAML(t, `
name: ovpn
type: openvpn
server: vpn.example.com
port: "1194"
username: u
`)
	_, err := openvpnEndpoint(&p)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotSupportType)
	assert.Contains(t, err.Error(), "openvpn:")

	// tls-auth + tls-crypt mutually exclusive
	p2 := proxyFromYAML(t, `
name: ovpn
type: openvpn
server: vpn.example.com
port: "1194"
ca: "ca"
username: u
tls-auth: "a"
tls-crypt: "b"
`)
	_, err = openvpnEndpoint(&p2)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotSupportType)

	// tls-crypt + tls-crypt-v2 mutually exclusive
	p3 := proxyFromYAML(t, `
name: ovpn
type: openvpn
server: vpn.example.com
port: "1194"
ca: "ca"
username: u
tls-crypt: "a"
tls-crypt-v2: "b"
`)
	_, err = openvpnEndpoint(&p3)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotSupportType)

	// tls-auth + tls-crypt-v2
	p4 := proxyFromYAML(t, `
name: ovpn
type: openvpn
server: vpn.example.com
port: "1194"
ca: "ca"
username: u
tls-auth: "a"
tls-crypt-v2: "b"
`)
	_, err = openvpnEndpoint(&p4)
	require.Error(t, err)

	// dev not tun
	p5 := proxyFromYAML(t, `
name: ovpn
type: openvpn
server: vpn.example.com
port: "1194"
ca: "ca"
username: u
dev: tap
`)
	_, err = openvpnEndpoint(&p5)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotSupportType)

	// invalid key-direction
	p6 := proxyFromYAML(t, `
name: ovpn
type: openvpn
server: vpn.example.com
port: "1194"
ca: "ca"
username: u
tls-auth: "a"
key-direction: "2"
`)
	_, err = openvpnEndpoint(&p6)
	require.Error(t, err)

	// invalid port
	p7 := proxyFromYAML(t, `
name: ovpn
type: openvpn
server: vpn.example.com
port: "not-a-port"
ca: "ca"
username: u
`)
	_, err = openvpnEndpoint(&p7)
	require.Error(t, err)
}

// --- Clash2sing + Patch 集成 ---

func TestClash2singOpenVPNMixed(t *testing.T) {
	c := clash.Clash{}
	require.NoError(t, yaml.Unmarshal([]byte(`
proxies:
  - name: ovpn1
    type: openvpn
    server: vpn.example.com
    port: "1194"
    ca: "ca-data"
    username: user
    password: pass
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
`), &c))
	out, eps, err := Clash2sing(c, model.SINGLATEST)
	require.NoError(t, err)
	assert.Len(t, out, 1)
	assert.Equal(t, "vmess1", out[0].Tag)
	require.Len(t, eps, 2)
	tags := []string{eps[0].Tag, eps[1].Tag}
	assert.Contains(t, tags, "ovpn1")
	assert.Contains(t, tags, "wg1")
	for _, ep := range eps {
		if ep.Tag == "ovpn1" {
			assert.Equal(t, "openvpn-client", ep.Type)
		}
	}
}

func TestClash2singOpenVPNErrorCollected(t *testing.T) {
	c := clash.Clash{}
	require.NoError(t, yaml.Unmarshal([]byte(`
proxies:
  - name: ovpn-bad
    type: openvpn
    server: vpn.example.com
    port: "1194"
    username: user
  - name: vmess1
    type: vmess
    server: 1.1.1.1
    port: "443"
    uuid: uuid
`), &c))
	out, eps, err := Clash2sing(c, model.SINGLATEST)
	assert.Error(t, err)
	assert.Len(t, out, 1)
	assert.Equal(t, "vmess1", out[0].Tag)
	assert.Empty(t, eps)
}

func TestClash2singOpenVPNDoesNotBlockOtherOnError(t *testing.T) {
	c := clash.Clash{}
	require.NoError(t, yaml.Unmarshal([]byte(`
proxies:
  - name: ovpn-bad
    type: openvpn
    server: vpn.example.com
    port: "1194"
    username: user
  - name: unknown
    type: unknown-proto
    server: 1.1.1.1
    port: "443"
  - name: vmess1
    type: vmess
    server: 1.1.1.1
    port: "443"
    uuid: uuid
`), &c))
	out, eps, err := Clash2sing(c, model.SINGLATEST)
	assert.Error(t, err)
	assert.Len(t, out, 1)
	assert.Empty(t, eps)
}

func TestPatchOpenVPNEndpoints(t *testing.T) {
	p := proxyFromYAML(t, `
name: ovpn1
type: openvpn
server: vpn.example.com
port: "1194"
ca: "ca-data"
username: u
password: p
`)
	ep, err := openvpnEndpoint(&p)
	require.NoError(t, err)
	m, err := patchTemplate(t, `{"outbounds":[]}`, nil, []*singbox.SingBoxEndpoint{ep}, "", "", nil, nil)
	require.NoError(t, err)
	raw, ok := m["endpoints"]
	require.True(t, ok)
	eps, ok := raw.([]any)
	require.True(t, ok)
	require.Len(t, eps, 1)
	epMap, ok := eps[0].(*singbox.SingBoxEndpoint)
	require.True(t, ok)
	assert.Equal(t, "openvpn-client", epMap.Type)
	b, err := json.Marshal(m)
	require.NoError(t, err)
	// outbounds should contain direct/block but not ovpn tag (endpoint is in endpoints, not outbounds)
	var decoded map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(b, &decoded))
	assert.Contains(t, string(decoded["endpoints"]), "openvpn-client")
	assert.Contains(t, string(decoded["endpoints"]), `"tag":"ovpn1"`)
	assert.NotContains(t, string(decoded["outbounds"]), `"tag":"ovpn1"`)
}

func TestOpenVPNEndpointJSON(t *testing.T) {
	p := proxyFromYAML(t, `
name: ovpn
type: openvpn
server: vpn.example.com
port: "1194"
ca: "my-ca"
username: u
password: p
tls-auth: "my-tls-auth"
key-direction: "1"
data-ciphers: [AES-256-GCM]
auth: SHA256
comp-lzo: "yes"
ping: 10
`)
	ep, err := openvpnEndpoint(&p)
	require.NoError(t, err)
	b, err := json.Marshal(ep)
	require.NoError(t, err)
	s := string(b)
	assert.Contains(t, s, `"server":"vpn.example.com"`)
	assert.Contains(t, s, `"server_port":1194`)
	assert.Contains(t, s, `"network":"udp"`)
	assert.Contains(t, s, `"certificate":["my-ca"]`)
	assert.Contains(t, s, `"type":"tls_auth"`)
	assert.Contains(t, s, `"direction":"server"`)
	assert.Contains(t, s, `"data_ciphers":["AES-256-GCM"]`)
	assert.Contains(t, s, `"auth":"SHA256"`)
	assert.Contains(t, s, `"compression_lzo":"yes"`)
	assert.Contains(t, s, `"ping_interval":"10s"`)
	assert.Contains(t, s, `"mode":"tls"`)
	// empty fields omitted
	assert.NotContains(t, s, "ping_restart")
}
