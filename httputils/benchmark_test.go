package httputils

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/tidwall/gjson"
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

func BenchmarkGetSingJSON(b *testing.B) {
	config := benchmarkSingJSON(1000)
	b.ReportAllocs()
	b.SetBytes(int64(len(config)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, err := getSing(config, "example.com", false)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGetSingBase64(b *testing.B) {
	payload := []byte(`{"add":"1.2.3.4","port":443,"id":"uuid","net":"tcp","ps":"node"}`)
	node := "vmess://" + base64.StdEncoding.EncodeToString(payload)
	config := []byte(base64.StdEncoding.EncodeToString([]byte(node)))
	b.ReportAllocs()
	b.SetBytes(int64(len(config)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, err := getSing(config, "example.com", false)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGetSingJSONGJSONSingleScan(b *testing.B) {
	config := benchmarkSingJSON(1000)
	b.ReportAllocs()
	b.SetBytes(int64(len(config)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, value := range gjson.GetBytes(config, "outbounds").Array() {
			_ = value.Get("type").String()
			_ = value.Get("tag").String()
			_ = value.Value()
		}
	}
}

// BenchmarkGetSingJSONGJSON approximates the former Valid + GetBytes path.
func BenchmarkGetSingJSONGJSON(b *testing.B) {
	config := benchmarkSingJSON(1000)
	b.ReportAllocs()
	b.SetBytes(int64(len(config)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !gjson.Valid(string(config)) {
			b.Fatal("invalid benchmark JSON")
		}
		for _, value := range gjson.GetBytes(config, "outbounds").Array() {
			_ = value.Get("type").String()
			_ = value.Get("tag").String()
			_ = value.Value()
		}
	}
}
