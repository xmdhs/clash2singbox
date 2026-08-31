package clash

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type boolHolder struct {
	T MyBool `yaml:"t"`
}

func TestMyBoolBoolValue(t *testing.T) {
	var h boolHolder
	require.NoError(t, yaml.Unmarshal([]byte("t: true\n"), &h))
	assert.Equal(t, MyBool(true), h.T)
}

func TestMyBoolIntValue(t *testing.T) {
	var h boolHolder
	require.NoError(t, yaml.Unmarshal([]byte("t: 1\n"), &h))
	assert.Equal(t, MyBool(true), h.T)

	var h0 boolHolder
	require.NoError(t, yaml.Unmarshal([]byte("t: 0\n"), &h0))
	assert.Equal(t, MyBool(false), h0.T)
}

func TestMyBoolInvalidValue(t *testing.T) {
	var h boolHolder
	err := yaml.Unmarshal([]byte("t: [\n"), &h)
	assert.Error(t, err)
	err = yaml.Unmarshal([]byte("t: nope\n"), &h)
	assert.Error(t, err)
}

type intHolder struct {
	N MyInt `yaml:"n"`
}

func TestMyIntIntValue(t *testing.T) {
	var h intHolder
	require.NoError(t, yaml.Unmarshal([]byte("n: 42\n"), &h))
	assert.Equal(t, MyInt(42), h.N)
}

func TestMyIntStringValue(t *testing.T) {
	var h intHolder
	require.NoError(t, yaml.Unmarshal([]byte("n: \"42\"\n"), &h))
	assert.Equal(t, MyInt(42), h.N)
}

func TestMyIntInvalidValue(t *testing.T) {
	// 语法错误不会进入解码器
	var h intHolder
	err := yaml.Unmarshal([]byte("n: [\n"), &h)
	assert.Error(t, err)
	// int 解码失败但 string 解码成功 → Atoi 失败
	err = yaml.Unmarshal([]byte("n: \"abc\"\n"), &h)
	assert.Error(t, err)
	// int 与 string 解码都失败才会走到 error 返回
	err = yaml.Unmarshal([]byte("n: [1, 2]\n"), &h)
	assert.Error(t, err)
}

type reservedHolder struct {
	R wgReserved `yaml:"r"`
}

func TestWgReservedStringValue(t *testing.T) {
	var h reservedHolder
	require.NoError(t, yaml.Unmarshal([]byte("r: \"abc\"\n"), &h))
	assert.Equal(t, []byte("abc"), h.R.Value)
}

func TestWgReservedListValue(t *testing.T) {
	var h reservedHolder
	require.NoError(t, yaml.Unmarshal([]byte("r: [1, 2, 3]\n"), &h))
	assert.Equal(t, []byte{1, 2, 3}, h.R.Value)
}

func TestWgReservedInvalidValue(t *testing.T) {
	// string 与 []uint8 解码都失败才会走到 error 返回
	var h reservedHolder
	err := yaml.Unmarshal([]byte("r: {a: b}\n"), &h)
	assert.Error(t, err)
}

// --- RealmOpts ---

func TestProxiesRealmOptsParsed(t *testing.T) {
	var p Proxies
	require.NoError(t, yaml.Unmarshal([]byte(`
name: hy2
type: hysteria2
server: server.com
port: "443"
realm-opts:
  enable: true
  server-url: https://realm.hy2.io
  token: public
  realm-id: my-cabin-1f3a8c2e9b
  stun-servers:
    - stun.nextcloud.com:3478
    - stun.sip.us:3478
`), &p))
	assert.Equal(t, MyBool(true), p.RealmOpts.Enable)
	assert.Equal(t, "https://realm.hy2.io", p.RealmOpts.ServerUrl)
	assert.Equal(t, "public", p.RealmOpts.Token)
	assert.Equal(t, "my-cabin-1f3a8c2e9b", p.RealmOpts.RealmId)
	assert.Equal(t, []string{"stun.nextcloud.com:3478", "stun.sip.us:3478"}, p.RealmOpts.StunServers)
}

func TestProxiesRealmOptsEnableInt(t *testing.T) {
	var p Proxies
	require.NoError(t, yaml.Unmarshal([]byte(`
name: hy2
type: hysteria2
server: server.com
port: "443"
realm-opts:
  enable: 1
  server-url: https://realm.hy2.io
  realm-id: rid
  stun-servers: ["stun.example.com:3478"]
`), &p))
	assert.Equal(t, MyBool(true), p.RealmOpts.Enable)

	var p2 Proxies
	require.NoError(t, yaml.Unmarshal([]byte(`
name: hy2
type: hysteria2
server: server.com
port: "443"
realm-opts:
  enable: 0
  server-url: https://realm.hy2.io
  realm-id: rid
  stun-servers: ["stun.example.com:3478"]
`), &p2))
	assert.Equal(t, MyBool(false), p2.RealmOpts.Enable)
}

func TestProxiesRealmOptsEmpty(t *testing.T) {
	var p Proxies
	require.NoError(t, yaml.Unmarshal([]byte(`
name: hy2
type: hysteria2
server: server.com
port: "443"
password: pass
`), &p))
	assert.Equal(t, MyBool(false), p.RealmOpts.Enable)
	assert.Equal(t, "", p.RealmOpts.ServerUrl)
	assert.Nil(t, p.RealmOpts.StunServers)
}
