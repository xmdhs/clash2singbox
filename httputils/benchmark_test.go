package httputils

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"
)

func benchmarkSingJSON(nodeCount int) []byte {
	var b bytes.Buffer
	b.WriteString(`{"outbounds":[`)
	for i := 0; i < nodeCount; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"type":"vmess","tag":"node-%d","server":"example.com","server_port":443}`, i)
	}
	b.WriteString(`]}`)
	return b.Bytes()
}

func BenchmarkParseSubBodyJSON(b *testing.B) {
	config := benchmarkSingJSON(1000)
	b.ReportAllocs()
	b.SetBytes(int64(len(config)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := parseSubBody(config); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseSubBodyBase64(b *testing.B) {
	payload := []byte(`{"add":"1.2.3.4","port":443,"id":"uuid","net":"tcp","ps":"node"}`)
	node := "vmess://" + base64.StdEncoding.EncodeToString(payload)
	config := []byte(base64.StdEncoding.EncodeToString([]byte(node)))
	b.ReportAllocs()
	b.SetBytes(int64(len(config)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := parseSubBody(config); err != nil {
			b.Fatal(err)
		}
	}
}
