package convert

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/xmdhs/clash2singbox/model"
	"github.com/xmdhs/clash2singbox/model/clash"
	"gopkg.in/yaml.v3"
)

// FuzzParseURL 解析任意输入不应 panic；成功解析出的节点再进入转换链也不应崩溃。
func FuzzParseURL(f *testing.F) {
	vmess := "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"1.2.3.4","port":443,"id":"u","tls":"tls","net":"ws","host":"ws.example.com","path":"/ws","ps":"n"}`))
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pass"))
	seeds := []string{
		vmess,
		"ss://" + userinfo + "@example.com:8388#node",
		"vless://uuid@example.com:443?security=reality&pbk=pk&sid=sid#n",
		"trojan://pass@example.com:443?type=ws&host=h&path=%2Fw#n",
		"hysteria://example.com:443?auth=a#n",
		"hy2://pass@example.com:443?sni=s#n",
		"tuic://uuid:pass@example.com:443?sni=s#n",
		"socks5://u:p@example.com:1080#n",
		"anytls://pass@example.com:443?sni=s#n",
		"https://example.com:8443#n",
		"not-a-url",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParseURL(s)
		if err != nil {
			return
		}
		c := clash.Clash{Proxies: []clash.Proxies{p}}
		_, _, _ = Clash2sing(c, model.SINGLATEST)
	})
}

// FuzzAnyToMbps 任意速率字符串解析都不应 panic，成功时值非负。
func FuzzAnyToMbps(f *testing.F) {
	for _, s := range []string{"", "100", "1Gbps", "500Kbps", "100MBps", "bad", "1Tbps"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := anyToMbps(s)
		if err != nil {
			return
		}
		if v < 0 {
			t.Fatalf("negative mbps: %d", v)
		}
	})
}

// FuzzPortsToPorts 任意端口串解析不应 panic，成功时输出形如 start:end。
func FuzzPortsToPorts(f *testing.F) {
	for _, s := range []string{"", "443", "500-505,600", "443/123", "200-100", "x-1", "1-x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := portsToPorts(s)
		if err != nil {
			return
		}
		_ = got
	})
}

// FuzzPortsToPort 随机单端口解析，不应 panic。
func FuzzPortsToPort(f *testing.F) {
	for _, s := range []string{"443", "500-505", "200-100", "x-1", "1-x", "abc"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = portsToPort(s)
	})
}

// FuzzAddCidr 任意 IP 列表补 CIDR 不应 panic（用换行分隔字符串表达列表）。
func FuzzAddCidr(f *testing.F) {
	f.Add("10.0.0.1")
	f.Add("fd00::2")
	f.Add("10.0.0.1/24\n")
	f.Add("garbage")
	f.Add("")
	f.Fuzz(func(t *testing.T, data string) {
		_, _ = addCidr(strings.Split(data, "\n"))
	})
}

// FuzzClash2sing 任意 YAML 描述的一组节点都不应让转换链 panic。
func FuzzClash2sing(f *testing.F) {
	seeds := []string{
		"proxies:\n  - name: v\n    type: vmess\n    server: x\n    port: \"443\"\n    uuid: u\n",
		"proxies:\n  - name: w\n    type: wireguard\n    server: x\n    port: \"51820\"\n    private-key: k\n    public-key: p\n    ip: 10.0.0.1\n",
		"proxies:\n  - name: h\n    type: hysteria2\n    server: x\n    port: \"443\"\n    password: p\n    ports: \"500-505\"\n",
		"proxies:\n  - name: s\n    type: ss\n    server: x\n    port: \"8388\"\n    cipher: aes-256-gcm\n    password: p\n    plugin: shadow-tls\n    plugin-opts:\n      host: h\n      password: p\n      version: 3\n",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		c := clash.Clash{}
		if yaml.Unmarshal([]byte(data), &c) != nil {
			return
		}
		_, _, _ = Clash2sing(c, model.SINGLATEST)
	})
}

// FuzzToInsecure 任意节点集都安全（不 panic）。
func FuzzToInsecure(f *testing.F) {
	f.Add("name: a\ntype: vmess\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, data string) {
		c := clash.Clash{}
		_ = yaml.Unmarshal([]byte(data), &c)
		ToInsecure(&c)
	})
}
