package convert

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
)

func TestFilterIncludeExclude(t *testing.T) {
	tags := []string{"HK-01", "HK-02", "JP-01", "SG-01"}
	inc, err := filter(true, "HK", tags)
	require.NoError(t, err)
	assert.Equal(t, []string{"HK-01", "HK-02"}, inc)

	exc, err := filter(false, "HK", tags)
	require.NoError(t, err)
	assert.Equal(t, []string{"JP-01", "SG-01"}, exc)
}

func TestFilterInvalidRegex(t *testing.T) {
	_, err := filter(true, "[", []string{"a"})
	assert.Error(t, err)
}

func TestGetTags(t *testing.T) {
	s := []singbox.SingBoxOut{
		{Tag: "n1", Type: "vmess"},
		{Tag: "n2", Type: "vmess", Ignored: true},
		{Tag: "n3", Type: "vmess", Visible: []string{"group"}},
		{Tag: "", Type: "vmess"},
	}
	assert.Equal(t, []string{"n1"}, getTags(s))
}

func TestGetForList(t *testing.T) {
	got := getForList([]int{1, 2, 3, 4}, func(v int) (int, bool) {
		if v%2 == 0 {
			return v * 10, true
		}
		return 0, false
	})
	assert.Equal(t, []int{20, 40}, got)
}

func TestToInsecure(t *testing.T) {
	c := clash.Clash{
		Proxies: []clash.Proxies{
			{Name: "a", Type: "vmess"},
			{Name: "b", Type: "trojan"},
		},
	}
	ToInsecure(&c)
	for _, p := range c.Proxies {
		assert.True(t, bool(p.SkipCertVerify))
	}
}

func TestPatchMapAutoOutbounds(t *testing.T) {
	s := []singbox.SingBoxOut{{Type: "vmess", Tag: "n1", Server: "x", ServerPort: 443}}
	// patchMap（Patch 使用的路径）在 outFields 下只生成 block，不生成 dns-out
	d, err := patchMap([]byte(`{}`), s, nil, "", "", nil, nil, true, true)
	require.NoError(t, err)
	out := d["outbounds"].([]any)
	require.Len(t, out, 5)

	count := map[string]int{}
	for _, item := range out {
		count[itemTag(item)]++
	}
	assert.Equal(t, 1, count["select"])
	assert.Equal(t, 1, count["urltest"])
	assert.Equal(t, 1, count["direct"])
	assert.Equal(t, 1, count["block"])
	assert.Equal(t, 1, count["n1"])

	sel := firstByTag(out, "select")
	selOb := itemOutbounds(sel)
	assert.Equal(t, "urltest", selOb[0].(string))
}

func TestPatchMapAvoidsDuplicateDirectFromTemplate(t *testing.T) {
	s := []singbox.SingBoxOut{{Type: "vmess", Tag: "n1"}}
	d, err := patchMap([]byte(`{"outbounds":[{"type":"direct","tag":"direct"}]}`), s, nil, "", "", nil, nil, true, true)
	require.NoError(t, err)
	out := d["outbounds"].([]any)
	count := map[string]int{}
	for _, item := range out {
		count[itemTag(item)]++
	}
	assert.Equal(t, 1, count["direct"])
}

func TestPatchMapIncludeFilter(t *testing.T) {
	s := []singbox.SingBoxOut{
		{Type: "vmess", Tag: "HK-01"},
		{Type: "vmess", Tag: "JP-01"},
	}
	d, err := patchMap([]byte(`{}`), s, nil, "HK", "", nil, nil, true, false)
	require.NoError(t, err)
	out := d["outbounds"].([]any)
	ut := firstByTag(out, "urltest")
	utOb := itemOutbounds(ut)
	require.Len(t, utOb, 1)
	assert.Equal(t, "HK-01", utOb[0].(string))
}

func TestPatchMapExternal(t *testing.T) {
	s := []singbox.SingBoxOut{{Type: "vmess", Tag: "n1"}}
	extOut := []any{map[string]any{"type": "direct", "tag": "ext1"}}
	d, err := patchMap([]byte(`{}`), s, nil, "", "", extOut, []string{"exttag"}, true, false)
	require.NoError(t, err)
	out := d["outbounds"].([]any)
	found := map[string]bool{}
	for _, item := range out {
		found[itemTag(item)] = true
	}
	assert.True(t, found["ext1"])
	// extags 追加在节点 tag 之后，extTag 应进入 urltest
	ut := firstByTag(out, "urltest")
	utOb := itemOutbounds(ut)
	assert.Equal(t, "n1", utOb[0].(string))
	assert.Equal(t, "exttag", utOb[1].(string))
}

func TestPatchMapAllPlaceholderAndTemplateFilter(t *testing.T) {
	tpl := `{
  "outbounds": [
    {"type":"urltest","tag":"auto","filter":[{"action":"include","keywords":"HK"}]},
    {"type":"selector","tag":"gate","outbounds":["auto","{all}"]}
  ]
}`
	s := []singbox.SingBoxOut{{Type: "vmess", Tag: "HK-01"}, {Type: "vmess", Tag: "JP-01"}}
	d, err := patchMap([]byte(tpl), s, nil, "", "", nil, nil, true, false)
	require.NoError(t, err)
	out := d["outbounds"].([]any)

	byTag := map[string]any{}
	for _, item := range out {
		byTag[itemTag(item)] = item
	}
	// filter 字段被移除
	assert.NotContains(t, byTag["auto"], "filter")
	// gate 的 outbounds 应包含 {all} 替换后的全部 tag 与 auto 关联的节点
	gateOb := itemOutbounds(byTag["gate"])
	assert.Contains(t, gateOb, "HK-01")
	assert.Contains(t, gateOb, "JP-01")
	assert.Contains(t, gateOb, "auto")
}

func TestApplyFilter(t *testing.T) {
	all := []string{"HK-01", "HK-02", "JP-01", "SG-01"}
	outbound := map[string]any{
		"type":   "urltest",
		"tag":    "a",
		"filter": []any{map[string]any{"action": "include", "keywords": "HK|JP"}},
	}
	got := applyFilter(outbound, all)
	assert.Equal(t, []string{"HK-01", "HK-02", "JP-01"}, got)

	outbound2 := map[string]any{
		"type":   "urltest",
		"filter": []any{map[string]any{"action": "exclude", "keywords": "02"}},
	}
	got2 := applyFilter(outbound2, all)
	assert.Equal(t, []string{"HK-01", "JP-01", "SG-01"}, got2)
}

func TestRemoveFilterField(t *testing.T) {
	outbound := map[string]any{"type": "urltest", "tag": "a", "filter": []any{}}
	res := removeFilterField(outbound).(map[string]any)
	assert.NotContains(t, res, "filter")
}

func TestPatchOutputsIndentedJSON(t *testing.T) {
	s := []singbox.SingBoxOut{{Type: "vmess", Tag: "n1"}}
	b, err := Patch([]byte(`{}`), s, nil, "", "", nil)
	require.NoError(t, err)
	// 格式化缩进
	assert.Contains(t, string(b), "\n")
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	require.NotNil(t, m["outbounds"])
}

// --- 类型无关的 outbound 访问辅助函数 ---

func itemTag(item any) string {
	switch v := item.(type) {
	case map[string]any:
		if t, ok := v["tag"].(string); ok {
			return t
		}
	case singbox.SingBoxOut:
		return v.Tag
	}
	return ""
}

func itemOutbounds(item any) []any {
	switch v := item.(type) {
	case map[string]any:
		if o, ok := v["outbounds"].([]any); ok {
			return o
		}
	case singbox.SingBoxOut:
		o := make([]any, len(v.Outbounds))
		for i, s := range v.Outbounds {
			o[i] = s
		}
		return o
	}
	return nil
}

func firstByTag(out []any, tag string) any {
	for _, item := range out {
		if itemTag(item) == tag {
			return item
		}
	}
	return nil
}
