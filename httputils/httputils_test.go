package httputils

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type staticRT struct {
	status int
	body   []byte
}

func (s staticRT) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: s.status,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader(s.body)),
	}, nil
}

func TestGetAnyYAMLSub(t *testing.T) {
	client := &http.Client{Transport: staticRT{status: 200, body: []byte(`
proxies:
  - name: hk-node
    type: vmess
    server: 1.2.3.4
    port: "443"
    uuid: uuid
`)}}
	c, singList, tags, err := GetAny(context.Background(), client, "https://example.com/sub", false)
	require.NoError(t, err)
	require.Len(t, c.Proxies, 1)
	assert.Equal(t, "hk-node", c.Proxies[0].Name)
	assert.Equal(t, "vmess", c.Proxies[0].Type)
	assert.Empty(t, singList)
	assert.Empty(t, tags)
}

func TestGetAnyAddTag(t *testing.T) {
	client := &http.Client{Transport: staticRT{status: 200, body: []byte(`
proxies:
  - name: hk-node
    type: vmess
    server: 1.2.3.4
    port: "443"
    uuid: uuid
`)}}
	c, _, _, err := GetAny(context.Background(), client, "https://example.com/sub", true)
	require.NoError(t, err)
	require.Len(t, c.Proxies, 1)
	assert.Equal(t, "hk-node[example.com]", c.Proxies[0].Name)
}

func TestGetAnyNonHTTPURUsesParseURL(t *testing.T) {
	// 非 http(s) 的订阅 URL 直接按节点链接解析，不发起网络请求
	client := &http.Client{Transport: staticRT{status: 200, body: []byte("should-not-be-used")}}
	_, _, _, err := GetAny(context.Background(), client, "vmess://", false)
	// vmess:// 空负载解析失败
	assert.Error(t, err)
}

func TestGetAnyHttpError(t *testing.T) {
	client := &http.Client{Transport: staticRT{status: 500, body: []byte("oops")}}
	_, _, _, err := GetAny(context.Background(), client, "https://example.com/sub", false)
	assert.Error(t, err)
}

func TestParseSubBodySingBoxJSON(t *testing.T) {
	config := []byte(`{
  "outbounds": [
    {"type":"vmess","tag":"node1","server":"x"},
    {"type":"direct","tag":"direct"},
    {"type":"selector","tag":"sel"}
  ]
}`)
	res, err := parseSubBody(config)
	require.NoError(t, err)
	require.Len(t, res.singNodes, 1)
	assert.Equal(t, "node1", res.singNodes[0]["tag"])
	assert.Equal(t, []string{"node1"}, res.singTags)
	assert.Nil(t, res.proxies)
}

func TestParseSubBodySingBoxJSONAddTag(t *testing.T) {
	res, err := parseSubBody([]byte(`{"outbounds":[{"type":"vmess","tag":"node1"}]}`))
	require.NoError(t, err)
	res.addHostSuffix("example.com")
	require.Len(t, res.singNodes, 1)
	assert.Equal(t, "node1[example.com]", res.singNodes[0]["tag"])
	assert.Equal(t, []string{"node1[example.com]"}, res.singTags)
}

func TestParseSubBodyBase64Subscription(t *testing.T) {
	body := "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"1.1.1.1","port":443,"id":"uuid","net":"tcp","ps":"n1"}`)) + "\n"
	config := base64.StdEncoding.EncodeToString([]byte(body))
	res, err := parseSubBody([]byte(config))
	require.NoError(t, err)
	assert.Nil(t, res.singNodes)
	assert.Nil(t, res.singTags)
	require.Len(t, res.proxies, 1)
	assert.Equal(t, "n1", res.proxies[0].Name)
	assert.Equal(t, "vmess", res.proxies[0].Type)
}

func TestParseSubBodyEmptyContent(t *testing.T) {
	_, err := parseSubBody([]byte(""))
	assert.Error(t, err)
}

func TestHttpGetStatusCode(t *testing.T) {
	client := &http.Client{Transport: staticRT{status: 404, body: []byte("not found")}}
	_, err := HttpGet(context.Background(), client, "https://example.com/sub", 1000)
	assert.Error(t, err)
	var hp Errpget
	require.ErrorAs(t, err, &hp)
	assert.Contains(t, hp.Error(), "not 200")
}

func TestHttpGetLimitedRead(t *testing.T) {
	client := &http.Client{Transport: staticRT{status: 200, body: []byte("1234567890")}}
	b, err := HttpGet(context.Background(), client, "https://example.com/sub", 5)
	require.NoError(t, err)
	assert.Equal(t, []byte("12345"), b)
}
