package convert

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
	"gopkg.in/yaml.v3"
)

func TestSsPluginV2Ray(t *testing.T) {
	p := clash.Proxies{}
	require.NoError(t, yaml.Unmarshal([]byte(`
plugin: v2ray-plugin
plugin-opts:
  mode: websocket
  tls: true
  host: ws.example.com
  path: /ws
  mux: true
`), &p))
	s := &singbox.SingBoxOut{}
	err := ssPlugin(p.PluginOpts, s, "v2ray-plugin")
	require.NoError(t, err)
	assert.Equal(t, "v2ray-plugin", s.Plugin)
	assert.Equal(t, "tls;host=ws.example.com;path=/ws;mode=websocket;mux", s.PluginOpts)
}

func TestSsPluginUnsupported(t *testing.T) {
	s := &singbox.SingBoxOut{}
	err := ssPlugin(yaml.Node{}, s, "not-a-plugin")
	assert.ErrorIs(t, err, ErrNotSupportPlugin)
}

func TestBackslashEscape(t *testing.T) {
	assert.Equal(t, "a\\;b\\=c\\\\d", backslashEscape(`a;b=c\d`))
	assert.Equal(t, "plain", backslashEscape("plain"))
}
