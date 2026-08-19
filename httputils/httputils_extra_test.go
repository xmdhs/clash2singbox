package httputils

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// urlRT 按完整 URL 返回对应 body，便于测多订阅聚合
type urlRT struct {
	m map[string][]byte
}

func (u urlRT) RoundTrip(req *http.Request) (*http.Response, error) {
	body, ok := u.m[req.URL.String()]
	if !ok {
		return &http.Response{StatusCode: 404, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(nil))}, nil
	}
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body))}, nil
}

type errRT struct{ err error }

func (e errRT) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, e.err
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestGetClash(t *testing.T) {
	client := &http.Client{Transport: staticRT{status: 200, body: []byte(`
proxies:
  - name: n1
    type: vmess
    server: 1.1.1.1
    port: "443"
    uuid: u
`)}}
	c, err := GetClash(context.Background(), client, "https://example.com/sub", false)
	require.NoError(t, err)
	require.Len(t, c.Proxies, 1)
	assert.Equal(t, "n1", c.Proxies[0].Name)
}

func TestGetClashError(t *testing.T) {
	client := &http.Client{Transport: staticRT{status: 500, body: []byte("oops")}}
	_, err := GetClash(context.Background(), client, "https://example.com/sub", false)
	assert.Error(t, err)
}

func TestGetAnyMultiBase64Subscriptions(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("https://example.com/1\nhttps://example.com/2"))
	client := &http.Client{Transport: urlRT{m: map[string][]byte{
		"https://example.com/1": []byte("proxies:\n  - name: a\n    type: vmess\n    server: 1.1.1.1\n    port: \"443\"\n    uuid: u\n"),
		"https://example.com/2": []byte("proxies:\n  - name: b\n    type: vmess\n    server: 2.2.2.2\n    port: \"443\"\n    uuid: u\n"),
	}}}
	c, _, _, err := GetAny(context.Background(), client, encoded, false)
	require.NoError(t, err)
	require.Len(t, c.Proxies, 2)
}

func TestGetAnyMultiPipedSubscriptions(t *testing.T) {
	client := &http.Client{Transport: urlRT{m: map[string][]byte{
		"https://example.com/1": []byte("proxies:\n  - name: a\n    type: vmess\n    server: 1.1.1.1\n    port: \"443\"\n    uuid: u\n"),
		"https://example.com/2": []byte("proxies:\n  - name: b\n    type: vmess\n    server: 2.2.2.2\n    port: \"443\"\n    uuid: u\n"),
	}}}
	c, _, _, err := GetAny(context.Background(), client, "https://example.com/1|https://example.com/2", false)
	require.NoError(t, err)
	require.Len(t, c.Proxies, 2)
}

func TestGetAnyAddTagGroups(t *testing.T) {
	client := &http.Client{Transport: staticRT{status: 200, body: []byte(`
proxies:
  - name: n1
    type: vmess
    server: 1.1.1.1
    port: "443"
    uuid: u
proxy-groups:
  - name: g1
    type: select
    proxies: [n1]
`)}}
	c, _, _, err := GetAny(context.Background(), client, "https://example.com/sub", true)
	require.NoError(t, err)
	require.Len(t, c.Proxies, 1)
	assert.Equal(t, "n1[example.com]", c.Proxies[0].Name)
	require.Len(t, c.ProxyGroup, 1)
	assert.Equal(t, "n1[example.com]", c.ProxyGroup[0].Proxies[0])
}

func TestGetAnyBadSubscriptionURL(t *testing.T) {
	client := &http.Client{}
	_, _, _, err := GetAny(context.Background(), client, "http://exa mple.com/sub", false)
	assert.Error(t, err)
}

func TestGetAnyDirectNode(t *testing.T) {
	// 非 http(s) 直接按节点链接解析
	vmess := "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"1.1.1.1","port":443,"id":"u","net":"tcp","ps":"node-a"}`))
	c, _, _, err := GetAny(context.Background(), &http.Client{}, vmess, false)
	require.NoError(t, err)
	require.Len(t, c.Proxies, 1)
	assert.Equal(t, "node-a", c.Proxies[0].Name)
}

func TestGetAnyInnerSubscriptionFails(t *testing.T) {
	// 订阅内容既不是 YAML 也不是有效订阅 → getSing 报错
	client := &http.Client{Transport: staticRT{status: 200, body: []byte("not a yaml\nor subscription")}}
	_, _, _, err := GetAny(context.Background(), client, "https://example.com/sub", false)
	assert.Error(t, err)
}

func TestGetAnySingJSONList(t *testing.T) {
	// 订阅内容是 sing-box JSON，走 singList 路径
	client := &http.Client{Transport: staticRT{status: 200, body: []byte(`{"outbounds":[
		{"type":"vmess","tag":"json-node","server":"x"},
		{"type":"direct","tag":"direct"}
	]}`)}}
	c, singList, tags, err := GetAny(context.Background(), client, "https://example.com/sub", true)
	require.NoError(t, err)
	assert.Empty(t, c.Proxies)
	require.Len(t, singList, 1)
	assert.Equal(t, "json-node[example.com]", singList[0]["tag"])
	assert.Equal(t, []string{"json-node[example.com]"}, tags)
}

func TestGetAnyTransportError(t *testing.T) {
	client := &http.Client{Transport: errRT{err: errors.New("boom")}}
	_, _, _, err := GetAny(context.Background(), client, "https://example.com/sub", false)
	assert.Error(t, err)
}

func TestGetSingPlainDecodedLines(t *testing.T) {
	vmess := base64.StdEncoding.EncodeToString([]byte(`{"add":"1.1.1.1","port":443,"id":"u","net":"tcp","ps":"a"}`))
	// 内部空行应被跳过（首尾空行会被 TrimSpace 吃掉）
	content := "vmess://" + vmess + "\n\nvmess://" + vmess
	outList, tags, proxies, err := getSing([]byte(content), "example.com", false)
	require.NoError(t, err)
	assert.Nil(t, outList)
	assert.Nil(t, tags)
	require.Len(t, proxies, 2)
	assert.Equal(t, "a", proxies[0].Name)
}

type failBody struct{}

func (failBody) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (failBody) Close() error             { return nil }

func TestHttpGetReadError(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: failBody{}}, nil
	})
	_, err := HttpGet(context.Background(), &http.Client{Transport: rt}, "https://example.com/sub", 1000)
	assert.Error(t, err)
}

func TestGetSingAllLinesFail(t *testing.T) {
	// base64 内容本身合法，但解码出的每行都是无法解析的节点
	content := base64.StdEncoding.EncodeToString([]byte("garbage-line-1\ngarbage-line-2"))
	_, _, _, err := getSing([]byte(content), "example.com", false)
	assert.Error(t, err)
}

func TestHttpGetNewRequestError(t *testing.T) {
	_, err := HttpGet(context.Background(), &http.Client{}, "://bad-url", 1000)
	assert.Error(t, err)
}

func TestHttpGetTransportError(t *testing.T) {
	client := &http.Client{Transport: errRT{err: errors.New("boom")}}
	_, err := HttpGet(context.Background(), client, "https://example.com/sub", 1000)
	assert.Error(t, err)
}
