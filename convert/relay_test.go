package convert

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmdhs/clash2singbox/model"
	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
	"gopkg.in/yaml.v3"
)

func TestRelayTooFewMembers(t *testing.T) {
	slm := map[string]singbox.SingBoxOut{"a": {Tag: "a"}}
	assert.Nil(t, relay(slm, []string{"a"}, "R"))
	assert.Nil(t, relay(slm, nil, "R"))
}

func TestRelayMissingMember(t *testing.T) {
	slm := map[string]singbox.SingBoxOut{"a": {Tag: "a"}, "b": {Tag: "b"}}
	assert.Nil(t, relay(slm, []string{"a", "missing", "b"}, "R"))
}

func TestRelayTwoHop(t *testing.T) {
	slm := map[string]singbox.SingBoxOut{
		"a": {Tag: "a", Server: "1.1.1.1"},
		"b": {Tag: "b", Server: "2.2.2.2"},
	}
	out := relay(slm, []string{"a", "b"}, "R")
	require.Len(t, out, 1)
	assert.Equal(t, "a-relay-R", out[0].Tag)
	assert.Equal(t, "b", out[0].Detour)
	assert.False(t, out[0].Ignored)
}

func TestRelayThreeHop(t *testing.T) {
	slm := map[string]singbox.SingBoxOut{
		"a": {Tag: "a"},
		"b": {Tag: "b"},
		"c": {Tag: "c"},
	}
	out := relay(slm, []string{"a", "b", "c"}, "R")
	require.Len(t, out, 2)

	// 返回顺序：先是中间跳 b，再是首跳 a
	assert.Equal(t, "b-relay-R", out[0].Tag)
	assert.Equal(t, "c", out[0].Detour)
	assert.True(t, out[0].Ignored)

	assert.Equal(t, "a-relay-R", out[1].Tag)
	assert.Equal(t, "b-relay-R", out[1].Detour)
	assert.False(t, out[1].Ignored)
}

func TestRelayChainViaClash2sing(t *testing.T) {
	// 通过 Clash2sing 集成验证 relay proxy-group 被展开
	c := clash.Clash{}
	require.NoError(t, yaml.Unmarshal([]byte(`
proxies:
  - name: a
    type: vmess
    server: 1.1.1.1
    port: "443"
    uuid: u
  - name: b
    type: vmess
    server: 2.2.2.2
    port: "443"
    uuid: u
  - name: c
    type: vmess
    server: 3.3.3.3
    port: "443"
    uuid: u
proxy-groups:
  - name: myrelay
    type: relay
    proxies: [a, b, c]
`), &c))

	out, _, err := Clash2sing(c, model.SINGLATEST)
	require.NoError(t, err)
	require.Len(t, out, 5)

	byTag := map[string]singbox.SingBoxOut{}
	for _, o := range out {
		byTag[o.Tag] = o
	}
	assert.Contains(t, byTag, "b-relay-myrelay")
	assert.Contains(t, byTag, "a-relay-myrelay")
	assert.Equal(t, "b-relay-myrelay", byTag["a-relay-myrelay"].Detour)
	assert.Equal(t, "c", byTag["b-relay-myrelay"].Detour)
	assert.True(t, byTag["b-relay-myrelay"].Ignored)
}
