package convert

import (
	"cmp"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/xmdhs/clash2singbox/model/clash"
)

// ParseURL 把节点分享链接解析为 Clash 节点。
// 支持 ss、vmess、vless、trojan、hysteria、hy2 / hysteria2、tuic、socks5、http / https、anytls。
func ParseURL(s string) (clash.Proxies, error) {
	s = strings.TrimSpace(s)
	u, err := url.Parse(s)
	if err != nil {
		return clash.Proxies{}, err
	}
	return parseURL(u, s)
}

// ParseURLFromURL 与 ParseURL 相同，但接受调用方已经解析好的 *url.URL；raw 是原始链接文本。保留以兼容旧调用方。
func ParseURLFromURL(u *url.URL, raw string) (clash.Proxies, error) {
	return parseURL(u, strings.TrimSpace(raw))
}

func parseURL(u *url.URL, raw string) (clash.Proxies, error) {
	var p clash.Proxies
	var err error
	switch u.Scheme {
	case "ss":
		p, err = parseSs(u)
	case "vmess":
		p, err = parseVmess(raw)
	case "vless":
		p, err = parseVless(u)
	case "trojan":
		p, err = parseTrojan(u)
	case "hysteria":
		p, err = parseHysteria(u)
	case "hy2", "hysteria2":
		p, err = parseHysteria2(u)
	case "tuic":
		p, err = parseTuic(u)
	case "socks5":
		p, err = parseSocks5(u)
	case "http", "https":
		p, err = parseHttp(u)
	case "anytls":
		p, err = parseAnytls(u)
	default:
		return clash.Proxies{}, fmt.Errorf("unsupported protocol: %s", u.Scheme)
	}
	if err != nil {
		return clash.Proxies{}, fmt.Errorf("%s: %w", raw, err)
	}
	return p, nil
}

// baseProxy 用链接里各协议共有的部分（#name、host、port）初始化节点。
func baseProxy(u *url.URL, typ string) clash.Proxies {
	return clash.Proxies{Type: typ, Name: u.Fragment, Server: u.Hostname(), Port: u.Port()}
}

// userPass 返回链接 userinfo 里的用户名与密码，缺省为空。
func userPass(u *url.URL) (string, string) {
	pass, _ := u.User.Password()
	return u.User.Username(), pass
}

// queryBool 报告布尔查询参数是否为真（"1" 或 "true"，忽略大小写）。
func queryBool(q url.Values, key string) clash.MyBool {
	v := q.Get(key)
	return clash.MyBool(v == "1" || strings.EqualFold(v, "true"))
}

// queryInt 解析整数查询参数，缺失或非法时为 0。
func queryInt(q url.Values, key string) clash.MyInt {
	n, _ := strconv.Atoi(q.Get(key))
	return clash.MyInt(n)
}

// queryList 解析逗号分隔的列表参数（如 alpn），缺失时为 nil。
func queryList(q url.Values, key string) []string {
	return splitComma(q.Get(key))
}

func splitComma(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func parseHttp(u *url.URL) (clash.Proxies, error) {
	p := baseProxy(u, "http")
	p.Username, p.Password = userPass(u)
	p.Tls = u.Scheme == "https"
	return p, nil
}

func parseSocks5(u *url.URL) (clash.Proxies, error) {
	p := baseProxy(u, "socks5")
	p.Username, p.Password = userPass(u)
	return p, nil
}

func parseTuic(u *url.URL) (clash.Proxies, error) {
	p := baseProxy(u, "tuic")
	p.Uuid, p.Password = userPass(u)
	q := u.Query()
	p.Sni = q.Get("sni")
	p.Alpn = queryList(q, "alpn")
	p.SkipCertVerify = queryBool(q, "skip-cert-verify")
	p.DisableSni = queryBool(q, "disable-sni")
	p.CongestionController = q.Get("congestion-controller")
	p.UdpRelayMode = q.Get("udp-relay-mode")
	p.ReduceRtt = queryBool(q, "reduce-rtt")
	p.HeartbeatInterval = queryInt(q, "heartbeat-interval")
	p.UdpOverStream = queryBool(q, "udp-over-stream")
	p.UdpOverStreamVersion = queryInt(q, "udp-over-stream-version")
	return p, nil
}

func parseHysteria2(u *url.URL) (clash.Proxies, error) {
	p := baseProxy(u, "hysteria2")
	p.Password = u.User.Username()
	q := u.Query()
	p.SkipCertVerify = queryBool(q, "insecure")
	p.Sni = q.Get("sni")
	p.Obfs = q.Get("obfs")
	p.ObfsPassword = q.Get("obfs-password")
	p.Ports = q.Get("mport")
	return p, nil
}

func parseHysteria(u *url.URL) (clash.Proxies, error) {
	p := baseProxy(u, "hysteria")
	q := u.Query()
	p.Alpn = queryList(q, "alpn")
	p.SkipCertVerify = queryBool(q, "insecure")
	p.AuthStr = q.Get("auth")
	p.Ports = q.Get("mport")
	p.Obfs = cmp.Or(q.Get("obfs"), q.Get("obfsParam"))
	p.Up = q.Get("upmbps")
	p.Down = q.Get("downmbps")
	p.FastOpen = queryBool(q, "fast-open")
	p.RecvWindowConn = queryInt(q, "recv-window-conn")
	p.RecvWindow = queryInt(q, "recv-window")
	p.DisableMtuDiscovery = queryBool(q, "disable-mtu-discovery")
	p.Fingerprint = q.Get("fingerprint")
	p.Protocol = q.Get("protocol")
	p.Sni = q.Get("sni")
	return p, nil
}

func parseTrojan(u *url.URL) (clash.Proxies, error) {
	p := baseProxy(u, "trojan")
	p.Password = u.User.Username()
	q := u.Query()
	p.Network = q.Get("type")
	if host := q.Get("host"); host != "" {
		p.WsOpts.Headers = map[string]string{"Host": host}
	}
	p.WsOpts.Path = q.Get("path")
	p.Alpn = queryList(q, "alpn")
	p.Sni = q.Get("sni")
	p.SkipCertVerify = queryBool(q, "skip-cert-verify") || queryBool(q, "allowInsecure")
	p.ClientFingerprint = cmp.Or(q.Get("client-fingerprint"), q.Get("fp"), q.Get("fingerprint"))
	return p, nil
}

func parseVless(u *url.URL) (clash.Proxies, error) {
	p := baseProxy(u, "vless")
	p.Uuid = u.User.String()
	q := u.Query()
	if security := q.Get("security"); security != "" && security != "none" {
		p.Tls = true
		if security == "reality" {
			p.RealityOpts.PublicKey = q.Get("pbk")
			p.RealityOpts.ShortId = q.Get("sid")
		}
	}
	p.Servername = cmp.Or(q.Get("sni"), q.Get("peer"))
	p.Flow = q.Get("flow")
	p.ClientFingerprint = q.Get("fp")
	p.Alpn = queryList(q, "alpn")
	p.SkipCertVerify = queryBool(q, "allowinsecure")
	p.Network = q.Get("type")

	host := cmp.Or(q.Get("host"), q.Get("obfsparam"))
	path := q.Get("path")
	switch p.Network {
	case "ws":
		p.WsOpts.Path = path
		if host != "" {
			p.WsOpts.Headers = map[string]string{"Host": host}
		}
		p.WsOpts.V2rayHttpUpgrade = q.Get("headerType") == "http"
	case "http":
		p.HTTPOpts.Path = []string{path}
		if host != "" {
			p.HTTPOpts.Headers = map[string][]string{"Host": {host}}
		}
	case "h2":
		p.H2Opts.Path = path
		if host != "" {
			p.H2Opts.Host = []string{host}
		}
	case "grpc":
		p.GrpcOpts.GrpcServiceName = path
	}
	// 开了 TLS 但没给 sni 时，用传输层的 Host 兜底
	if p.Tls && p.Servername == "" {
		p.Servername = p.WsOpts.Headers["Host"]
		if p.Servername == "" && len(p.HTTPOpts.Headers["Host"]) > 0 {
			p.Servername = p.HTTPOpts.Headers["Host"][0]
		}
	}
	return p, nil
}

func parseVmess(raw string) (clash.Proxies, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(raw, "vmess://"))
	if err != nil {
		return clash.Proxies{}, err
	}
	var v struct {
		Ps   string `json:"ps"`
		Add  string `json:"add"`
		Port any    `json:"port"` // 数字或字符串
		Id   string `json:"id"`
		Aid  any    `json:"aid"` // 数字或字符串
		Scy  string `json:"scy"`
		Net  string `json:"net"`
		Host string `json:"host"`
		Path string `json:"path"`
		Tls  string `json:"tls"`
		Sni  string `json:"sni"`
		Alpn string `json:"alpn"`
		Fp   string `json:"fp"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return clash.Proxies{}, err
	}
	alterID, _ := strconv.Atoi(jsonNumberString(v.Aid))
	p := clash.Proxies{
		Type:              "vmess",
		Name:              v.Ps,
		Server:            v.Add,
		Port:              jsonNumberString(v.Port),
		Uuid:              v.Id,
		Cipher:            v.Scy,
		AlterId:           clash.MyInt(alterID),
		Network:           v.Net,
		Alpn:              splitComma(v.Alpn),
		ClientFingerprint: v.Fp,
	}
	if v.Tls == "tls" {
		p.Tls = true
		p.Servername = v.Sni
	}
	switch v.Net {
	case "ws":
		p.WsOpts.Path = v.Path
		p.WsOpts.Headers = map[string]string{"Host": v.Host}
	case "http":
		p.HTTPOpts.Path = []string{v.Path}
		p.HTTPOpts.Headers = map[string][]string{"Host": {v.Host}}
	case "h2":
		p.H2Opts.Path = v.Path
		p.H2Opts.Host = []string{v.Host}
	case "grpc":
		p.GrpcOpts.GrpcServiceName = v.Path
	}
	return p, nil
}

// jsonNumberString 把 vmess 链接里既可能是数字也可能是字符串的字段统一成字符串。
func jsonNumberString(v any) string {
	switch n := v.(type) {
	case string:
		return n
	case float64:
		return strconv.FormatFloat(n, 'f', -1, 64)
	}
	return ""
}

func parseSs(u *url.URL) (clash.Proxies, error) {
	p := baseProxy(u, "ss")
	// userinfo 有两种写法：base64(method:password) 或明文 method:password
	if password, ok := u.User.Password(); ok {
		p.Cipher = u.User.Username()
		p.Password = password
	} else {
		decoded, err := base64.RawURLEncoding.DecodeString(u.User.Username())
		if err != nil {
			return clash.Proxies{}, fmt.Errorf("invalid ss link")
		}
		if cipher, pass, ok := strings.Cut(string(decoded), ":"); ok {
			p.Cipher, p.Password = cipher, pass
		}
	}
	q := u.Query()
	if plugin := q.Get("plugin"); plugin != "" {
		if err := parseSsPlugin(&p, plugin); err != nil {
			return clash.Proxies{}, err
		}
	}
	p.Tfo = bool(queryBool(q, "tfo"))
	return p, nil
}

// parseSsPlugin 解析 SIP002 的 plugin 参数（"插件名;k=v;flag"）为 Clash 的 plugin / plugin-opts。
func parseSsPlugin(p *clash.Proxies, plugin string) error {
	name, rest, ok := strings.Cut(plugin, ";")
	if !ok {
		return fmt.Errorf("invalid plugin: %s", plugin)
	}
	opts := map[string]string{}
	for part := range strings.SplitSeq(rest, ";") {
		k, v, hasValue := strings.Cut(part, "=")
		switch {
		case hasValue:
			opts[k] = v
		case k == "tls": // v2ray-plugin 用裸标志 tls 表示启用 TLS
			opts["tls"] = "true"
		}
	}
	switch name {
	case "obfs-local", "simple-obfs":
		p.Plugin = "obfs"
		pluginOpts := map[string]string{"mode": opts["obfs"]}
		if host, ok := opts["obfs-host"]; ok {
			pluginOpts["host"] = host
		}
		return p.PluginOpts.Encode(pluginOpts)
	case "v2ray-plugin":
		p.Plugin = "v2ray-plugin"
		pluginOpts := map[string]any{"mode": opts["mode"], "host": opts["host"]}
		if _, ok := opts["tls"]; ok {
			pluginOpts["tls"] = true
		}
		return p.PluginOpts.Encode(pluginOpts)
	}
	return nil
}

func parseAnytls(u *url.URL) (clash.Proxies, error) {
	p := baseProxy(u, "anytls")
	p.Password = u.User.Username()
	q := u.Query()
	p.Servername = q.Get("sni")
	p.SkipCertVerify = queryBool(q, "insecure")
	return p, nil
}
