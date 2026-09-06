package httputils

import (
	"encoding/base64"
	"testing"
)

// FuzzParseSubBody 任意订阅内容解析都不应 panic（覆盖 JSON / YAML / base64 / 纯文本路径）。
func FuzzParseSubBody(f *testing.F) {
	vmess := "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"1.1.1.1","port":443,"id":"u","net":"tcp","ps":"a"}`))
	seeds := []string{
		`{"outbounds":[{"type":"vmess","tag":"json-node"},{"type":"direct","tag":"direct"}]}`,
		base64.StdEncoding.EncodeToString([]byte(vmess + "\n" + vmess)),
		vmess,
		"proxies:\n  - name: a\n    type: vmess\n",
		"plain text subscription content",
		"",
		"{",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := parseSubBody(data)
		if err == nil {
			res.addHostSuffix("example.com")
		}
	})
}
