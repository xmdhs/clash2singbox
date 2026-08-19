package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const yamlIn = `
proxies:
  - name: p1
    type: vmess
    server: 1.2.3.4
    port: "443"
    uuid: u
`

func TestRunFilePath(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "in.yaml")
	require.NoError(t, os.WriteFile(inFile, []byte(yamlIn), 0o644))
	tplFile := filepath.Join(dir, "tpl.json")
	require.NoError(t, os.WriteFile(tplFile, []byte(`{"outbounds":[]}`), 0o644))
	outFile := filepath.Join(dir, "out.json")

	run("", inFile, outFile, tplFile, "", "", false)

	b, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Contains(t, string(b), "p1")
}

func TestRunTemplateFallback(t *testing.T) {
	// template 文件不存在时回退到内嵌模板
	dir := t.TempDir()
	inFile := filepath.Join(dir, "in.yaml")
	require.NoError(t, os.WriteFile(inFile, []byte(yamlIn), 0o644))
	outFile := filepath.Join(dir, "out.json")

	run("", inFile, outFile, filepath.Join(dir, "missing-template.json"), "", "", false)

	b, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Contains(t, string(b), "p1")
}

func TestRunInsecureIncludesAllNodes(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "in.yaml")
	require.NoError(t, os.WriteFile(inFile, []byte(yamlIn), 0o644))
	outFile := filepath.Join(dir, "out.json")

	run("", inFile, outFile, filepath.Join(dir, "missing.json"), "", "", true)

	b, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Contains(t, string(b), "p1")
}

func TestRunNoArgsPanics(t *testing.T) {
	require.Panics(t, func() { run("", "", "out", "tpl", "", "", false) })
}

func TestRunBadPathPanics(t *testing.T) {
	require.Panics(t, func() { run("", filepath.Join(t.TempDir(), "nope.yaml"), "out", "tpl", "", "", false) })
}

type mainRT struct{ body []byte }

func (m mainRT) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(m.body))}, nil
}

func TestRunURLJSONSub(t *testing.T) {
	// http 订阅返回 sing-box JSON → 触发 singList 路径
	prev := httpClient
	httpClient = &http.Client{Transport: mainRT{body: []byte(`{"outbounds":[{"type":"vmess","tag":"json-node","server":"x"}]}`)}}
	defer func() { httpClient = prev }()

	outFile := filepath.Join(t.TempDir(), "out.json")
	run("https://example.com/sub", "", outFile, filepath.Join(t.TempDir(), "missing.json"), "", "", false)
	b, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Contains(t, string(b), "json-node")
}

func TestMainFunction(t *testing.T) {
	// 默认参数时 main 会因 url/i 均为空而 panic，从而覆盖 main() 本身
	require.Panics(t, main)
}

func TestRunURL(t *testing.T) {
	// url 为节点链接（非 http），不触发网络请求
	vmess := "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"1.2.3.4","port":443,"id":"u","net":"tcp","ps":"p1"}`))
	outFile := filepath.Join(t.TempDir(), "out.json")
	run(vmess, "", outFile, filepath.Join(t.TempDir(), "missing.json"), "", "", false)
	b, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Contains(t, string(b), "p1")
}

func TestRunBadURLPanics(t *testing.T) {
	require.Panics(t, func() { run("://bad", "", "out", "tpl", "", "", false) })
}

func TestRunBadYAMLPanics(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(inFile, []byte("a: [\n  {"), 0o644))
	require.Panics(t, func() { run("", inFile, filepath.Join(dir, "out"), "tpl", "", "", false) })
}

func TestRunClashErrorLogged(t *testing.T) {
	// 转换失败的节点只打印日志，不中断输出
	dir := t.TempDir()
	inFile := filepath.Join(dir, "in.yaml")
	require.NoError(t, os.WriteFile(inFile, []byte(`
proxies:
  - name: bwg
    type: wireguard
    server: example.com
    port: "51820"
    private-key: p
    ip: not-an-ip
`), 0o644))
	outFile := filepath.Join(dir, "out.json")
	run("", inFile, outFile, filepath.Join(dir, "missing.json"), "", "", false)
	b, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.NotEmpty(t, b)
}

func TestRunTemplateIsDirPanics(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "in.yaml")
	require.NoError(t, os.WriteFile(inFile, []byte(yamlIn), 0o644))
	require.Panics(t, func() { run("", inFile, filepath.Join(dir, "out"), dir, "", "", false) })
}

func TestRunBadIncludePanics(t *testing.T) {
	dir := t.TempDir()
	inFile := filepath.Join(dir, "in.yaml")
	require.NoError(t, os.WriteFile(inFile, []byte(yamlIn), 0o644))
	require.Panics(t, func() { run("", inFile, filepath.Join(dir, "out"), filepath.Join(dir, "missing.json"), "[", "", false) })
}
