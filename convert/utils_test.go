package convert

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
)

// patchTemplate 以命令行版本（Patch）的选项对模板 tpl 打补丁，返回补丁后的模板。
func patchTemplate(t *testing.T, tpl string, s []singbox.SingBoxOut, eps []*singbox.SingBoxEndpoint, include, exclude string, extOut []any, extags []string) (map[string]any, error) {
	t.Helper()
	var d map[string]any
	require.NoError(t, json.Unmarshal([]byte(tpl), &d))
	err := patch(d, s, eps, extOut, extags, patchOptions{include: include, exclude: exclude, urltest: true, keepTemplate: true})
	return d, err
}

func TestFilterByRegexp(t *testing.T) {
	tags := []string{"HK-01", "HK-02", "JP-01", "SG-01"}
	inc, err := filterByRegexp(tags, "HK", true)
	require.NoError(t, err)
	assert.Equal(t, []string{"HK-01", "HK-02"}, inc)

	exc, err := filterByRegexp(tags, "HK", false)
	require.NoError(t, err)
	assert.Equal(t, []string{"JP-01", "SG-01"}, exc)
}

func TestFilterByRegexpInvalid(t *testing.T) {
	_, err := filterByRegexp([]string{"a"}, "[", true)
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

func TestPatchAutoOutbounds(t *testing.T) {
	s := []singbox.SingBoxOut{{Type: "vmess", Tag: "n1", Server: "x", ServerPort: 443}}
	// 命令行版本面向最新 sing-box，不补 block / dns-out 这类已废弃的 outbound
	d, err := patchTemplate(t, `{}`, s, nil, "", "", nil, nil)
	require.NoError(t, err)
	out := d["outbounds"].([]any)
	require.Len(t, out, 4)

	count := map[string]int{}
	for _, item := range out {
		count[itemTag(item)]++
	}
	assert.Equal(t, 1, count["select"])
	assert.Equal(t, 1, count["urltest"])
	assert.Equal(t, 1, count["direct"])
	assert.Equal(t, 1, count["n1"])
	assert.Equal(t, 0, count["block"])

	sel := firstByTag(out, "select")
	assert.Equal(t, "urltest", itemOutbounds(sel)[0].(string))
}

func TestPatchAvoidsDuplicateDirectFromTemplate(t *testing.T) {
	s := []singbox.SingBoxOut{{Type: "vmess", Tag: "n1"}}
	d, err := patchTemplate(t, `{"outbounds":[{"type":"direct","tag":"direct"}]}`, s, nil, "", "", nil, nil)
	require.NoError(t, err)
	out := d["outbounds"].([]any)
	count := map[string]int{}
	for _, item := range out {
		count[itemTag(item)]++
	}
	assert.Equal(t, 1, count["direct"])
}

func TestPatchIncludeFilter(t *testing.T) {
	s := []singbox.SingBoxOut{
		{Type: "vmess", Tag: "HK-01"},
		{Type: "vmess", Tag: "JP-01"},
	}
	d, err := patchTemplate(t, `{}`, s, nil, "HK", "", nil, nil)
	require.NoError(t, err)
	out := d["outbounds"].([]any)
	utOb := itemOutbounds(firstByTag(out, "urltest"))
	require.Len(t, utOb, 1)
	assert.Equal(t, "HK-01", utOb[0].(string))
}

func TestPatchSkipsUrltestWhenNothingMatches(t *testing.T) {
	// 过滤后没有节点时不生成 select / urltest，否则 selector 的默认出站会指向不存在的 urltest
	s := []singbox.SingBoxOut{{Type: "vmess", Tag: "JP-01"}}
	d, err := patchTemplate(t, `{}`, s, nil, "HK", "", nil, nil)
	require.NoError(t, err)
	out := d["outbounds"].([]any)
	assert.Nil(t, firstByTag(out, "select"))
	assert.Nil(t, firstByTag(out, "urltest"))
	assert.NotNil(t, firstByTag(out, "JP-01"))
}

func TestPatchExternal(t *testing.T) {
	s := []singbox.SingBoxOut{{Type: "vmess", Tag: "n1"}}
	extOut := []any{map[string]any{"type": "direct", "tag": "ext1"}}
	d, err := patchTemplate(t, `{}`, s, nil, "", "", extOut, []string{"exttag"})
	require.NoError(t, err)
	out := d["outbounds"].([]any)
	found := map[string]bool{}
	for _, item := range out {
		found[itemTag(item)] = true
	}
	assert.True(t, found["ext1"])
	// extags 追加在节点 tag 之后，且应进入 urltest
	utOb := itemOutbounds(firstByTag(out, "urltest"))
	assert.Equal(t, "n1", utOb[0].(string))
	assert.Equal(t, "exttag", utOb[1].(string))
}

func TestPatchAllPlaceholderAndTemplateFilter(t *testing.T) {
	tpl := `{
  "outbounds": [
    {"type":"urltest","tag":"auto","filter":[{"action":"include","keywords":"HK"}]},
    {"type":"selector","tag":"gate","outbounds":["auto","{all}"]}
  ]
}`
	s := []singbox.SingBoxOut{{Type: "vmess", Tag: "HK-01"}, {Type: "vmess", Tag: "JP-01"}}
	d, err := patchTemplate(t, tpl, s, nil, "", "", nil, nil)
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
	assert.Equal(t, []string{"HK-01", "HK-02", "JP-01"}, applyFilter(outbound, all))

	outbound2 := map[string]any{
		"type":   "urltest",
		"filter": []any{map[string]any{"action": "exclude", "keywords": "02"}},
	}
	assert.Equal(t, []string{"HK-01", "JP-01", "SG-01"}, applyFilter(outbound2, all))
}

func TestPatchOutputsIndentedJSON(t *testing.T) {
	s := []singbox.SingBoxOut{{Type: "vmess", Tag: "n1"}}
	b, err := Patch([]byte(`{}`), s, nil, "", "", nil)
	require.NoError(t, err)
	assert.Contains(t, string(b), "\n")
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	require.NotNil(t, m["outbounds"])
}

func TestPatchRejectsNullTemplate(t *testing.T) {
	_, err := Patch([]byte(`null`), nil, nil, "", "", nil)
	assert.Error(t, err)
	_, err = PatchMap([]byte(`null`), nil, nil, "", "", nil, nil, false, false)
	assert.Error(t, err)
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
