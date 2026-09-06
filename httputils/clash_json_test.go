package httputils

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSubBodyValidJSONScalar(t *testing.T) {
	// 有效但无法识别的 JSON 视为空订阅，不报错
	res, err := parseSubBody([]byte(`true`))
	require.NoError(t, err)
	assert.Empty(t, res.singNodes)
	assert.Empty(t, res.singTags)
	assert.Empty(t, res.proxies)
}

func TestParseSubBodyValidJSONWithoutOutbounds(t *testing.T) {
	res, err := parseSubBody([]byte(`{"log":{}}`))
	require.NoError(t, err)
	assert.Empty(t, res.singNodes)
	assert.Empty(t, res.singTags)
	assert.Empty(t, res.proxies)
}

func TestParseSubBodyJSONClashDocument(t *testing.T) {
	// JSON 是 YAML 的子集，含 proxies 的 JSON 按 Clash 配置解析
	res, err := parseSubBody([]byte(`{"proxies":[{"name":"n1"}]}`))
	require.NoError(t, err)
	require.Len(t, res.proxies, 1)
	assert.Equal(t, "n1", res.proxies[0].Name)
	assert.Empty(t, res.singNodes)
}

func TestGetAnyJSONClashDocumentUsesYAML(t *testing.T) {
	client := &http.Client{Transport: staticRT{status: http.StatusOK, body: []byte(`{"proxies":[{"name":"n1","type":"vmess","server":"example.com","port":"443","uuid":"u"}]}`)}}

	c, singList, tags, err := GetAny(context.Background(), client, "https://example.com/sub", false)
	require.NoError(t, err)
	require.Len(t, c.Proxies, 1)
	assert.Equal(t, "n1", c.Proxies[0].Name)
	assert.Empty(t, singList)
	assert.Empty(t, tags)
}

func TestParseSubBodyObjectOutbound(t *testing.T) {
	// outbounds 写成单个对象时按一个 outbound 处理
	res, err := parseSubBody([]byte(`{"outbounds":{"type":"vmess","tag":"n1"}}`))
	require.NoError(t, err)
	require.Len(t, res.singNodes, 1)
	assert.Equal(t, "n1", res.singNodes[0]["tag"])
	assert.Equal(t, []string{"n1"}, res.singTags)
	assert.Empty(t, res.proxies)
}

func TestParseSubBodyAddTagSkipsShadowTLS(t *testing.T) {
	res, err := parseSubBody([]byte(`{"outbounds":[{"type":"vmess","tag":"n1"},{"type":"shadowtls","tag":"stls"}]}`))
	require.NoError(t, err)
	res.addHostSuffix("example.com")
	require.Len(t, res.singNodes, 2)
	assert.Equal(t, "n1[example.com]", res.singNodes[0]["tag"])
	assert.Equal(t, "stls[example.com]", res.singNodes[1]["tag"])
	// shadowtls 只作 detour，不进入可选 tag
	assert.Equal(t, []string{"n1[example.com]"}, res.singTags)
	assert.Empty(t, res.proxies)
}
