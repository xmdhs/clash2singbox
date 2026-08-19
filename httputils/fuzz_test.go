package httputils

import (
	"encoding/base64"
	"testing"
)

// FuzzGetSing 任意订阅内容解析都不应 panic（覆盖 JSON / base64 / 纯文本路径）。
func FuzzGetSing(f *testing.F) {
	vmess := "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"1.1.1.1","port":443,"id":"u","net":"tcp","ps":"a"}`))
	seeds := []string{
		`{"outbounds":[{"type":"vmess","tag":"json-node"},{"type":"direct","tag":"direct"}]}`,
		base64.StdEncoding.EncodeToString([]byte(vmess + "\n" + vmess)),
		vmess,
		"plain text subscription content",
		"",
		"{",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _ = getSing(data, "example.com", false)
		_, _, _, _ = getSing(data, "example.com", true)
	})
}
