package convert

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmdhs/clash2singbox/model/singbox"
)

func TestPatchMapFromMapMatchesByteEntry(t *testing.T) {
	tpl := []byte(`{
		"custom": {"keep": true},
		"outbounds": []
	}`)
	s := []singbox.SingBoxOut{{Type: "vmess", Tag: "n1", Server: "example.com"}}
	eps := []*singbox.SingBoxEndpoint{{Type: "wireguard", Tag: "ep1"}}
	extOut := []any{map[string]any{"type": "direct", "tag": "external"}}
	extags := []string{"external-tag"}

	want, err := PatchMap(tpl, s, eps, "", "", extOut, extags, true, true)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(tpl, &decoded))
	got, err := PatchMapFromMap(decoded, s, eps, "", "", extOut, extags, true, true)
	require.NoError(t, err)
	assert.Equal(t, want, got)
	assert.Equal(t, true, got["custom"].(map[string]any)["keep"])
}

func TestPatchMapFromMapRejectsNil(t *testing.T) {
	_, err := PatchMapFromMap(nil, nil, nil, "", "", nil, nil, false, false)
	assert.Error(t, err)
}
