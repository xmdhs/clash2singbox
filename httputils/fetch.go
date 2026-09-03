package httputils

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/samber/lo"
	"github.com/tidwall/gjson"
	"github.com/xmdhs/clash2singbox/convert"
	"github.com/xmdhs/clash2singbox/model/clash"
	"gopkg.in/yaml.v3"
)

// bodyKind 嗅探订阅 body 类型，只走一条解析路，避免 JSON/YAML/行订阅 2~3 遍重复解析。
type bodyKind int

const (
	kindUnknown bodyKind = iota
	kindJSON
	kindYAML
	kindLines
)

// sniffBodyKind 按去空白后首字节嗅探：
// '{' -> JSON；包含顶层 "proxies:" 键 -> YAML；否则按行订阅处理。
func sniffBodyKind(b []byte) bodyKind {
	t := bytes.TrimSpace(b)
	if len(t) == 0 {
		return kindUnknown
	}
	if t[0] == '{' {
		return kindJSON
	}
	for _, line := range bytes.Split(t, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if bytes.HasPrefix(line, []byte("proxies:")) {
			return kindYAML
		}
	}
	return kindLines
}

// looksLikeBase64 粗判内容是否像 base64（字符集 + 长度%4），
// 保留标准 Base64 解码器对 CR/LF 折行的兼容性，避免对明显不是 base64
// 的整包 URL 付一次解码分配。
func looksLikeBase64(s string) bool {
	s = strings.TrimSpace(s)
	length := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\r' || c == '\n' {
			continue
		}
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=' {
			length++
			continue
		}
		return false
	}
	return length >= 8 && length%4 == 0
}

// splitSubURLs 解析 sub 参数：单 URL 时尝试 base64 多链接展开。
func splitSubURLs(u string) []string {
	urls := strings.Split(u, "|")
	if len(urls) == 1 && looksLikeBase64(u) {
		if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(u)); err == nil {
			lines := lo.FilterMap(bytes.Split(decoded, []byte{'\n'}), func(b []byte, _ int) (string, bool) {
				s := string(bytes.TrimSpace(b))
				return s, s != ""
			})
			if len(lines) > 0 {
				return lines
			}
		}
	}
	return urls
}

type subResult struct {
	idx       int
	proxies   []clash.Proxies
	groups    []clash.ProxyGroup
	singNodes []map[string]any
	singTags  []string
}

// fetchOneURL 抓取并解析单个订阅 URL（无状态，可并发）。
func fetchOneURL(ctx context.Context, hc *http.Client, raw string, host string, addTag bool, idx int) (subResult, error) {
	res := subResult{idx: idx}
	parsed, err := url.Parse(raw)
	if err != nil {
		return res, fmt.Errorf("GetAny: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		node, err := convert.ParseURLFromURL(parsed, raw)
		if err != nil {
			return res, err
		}
		res.proxies = []clash.Proxies{node}
	} else {
		b, err := HttpGet(ctx, hc, raw, 1000*1000*10)
		if err != nil {
			return res, err
		}
		proxies, groups, singNodes, singTags, err := parseSubBody(b, host, addTag)
		if err != nil {
			return res, err
		}
		res.proxies = proxies
		res.groups = groups
		res.singNodes = singNodes
		res.singTags = singTags
	}
	if addTag {
		for i := range res.proxies {
			res.proxies[i].Name = res.proxies[i].Name + "[" + host + "]"
		}
		for i := range res.groups {
			for j := range res.groups[i].Proxies {
				res.groups[i].Proxies[j] = res.groups[i].Proxies[j] + "[" + host + "]"
			}
		}
	}
	return res, nil
}

// parseSubBody 按嗅探结果选择解析路径，并为非 JSON 内容保留 YAML fallback。
func parseSubBody(b []byte, host string, addTag bool) (proxies []clash.Proxies, groups []clash.ProxyGroup, singNodes []map[string]any, singTags []string, err error) {
	switch sniffBodyKind(b) {
	case kindJSON:
		s, t, validJSON, singJSON := parseSingJSON(b, host, addTag)
		if validJSON {
			if singJSON {
				return nil, nil, s, t, nil
			}
			// JSON Clash（含 proxies）继续 YAML 解码（与旧行为一致）。
			var tc clash.Clash
			if yerr := yaml.Unmarshal(b, &tc); yerr == nil && len(tc.Proxies) > 0 {
				return tc.Proxies, tc.ProxyGroup, nil, nil, nil
			}
			return getSingParts(b, host, addTag)
		}
		// 非法 JSON 回退到行订阅
		return getSingParts(b, host, addTag)
	case kindYAML:
		var tc clash.Clash
		if yerr := yaml.Unmarshal(b, &tc); yerr == nil && len(tc.Proxies) > 0 {
			return tc.Proxies, tc.ProxyGroup, nil, nil, nil
		}
		return getSingParts(b, host, addTag)
	default:
		// 保留旧行为：非 JSON 内容也尝试完整 Clash YAML，
		// 以兼容 mixed-port/proxy-groups 等字段位于 proxies 之前的配置。
		var tc clash.Clash
		if yerr := yaml.Unmarshal(b, &tc); yerr == nil && len(tc.Proxies) > 0 {
			return tc.Proxies, tc.ProxyGroup, nil, nil, nil
		}
		return getSingParts(b, host, addTag)
	}
}

// getSingParts 是 getSing 的拆分版：行订阅逐行 ParseURL。
func getSingParts(config []byte, host string, addTag bool) ([]clash.Proxies, []clash.ProxyGroup, []map[string]any, []string, error) {
	// 有效 JSON（含标量 true、{"log":{}}、{"proxies":[...]} 等）保持旧行为直接返回，
	// 不再回退到逐行订阅解析（与 parseSingJSON 的 validJSON 语义一致）。
	trimmed := bytes.TrimSpace(config)
	if len(trimmed) > 0 && gjson.ValidBytes(trimmed) {
		if outs := gjson.GetBytes(trimmed, "outbounds"); outs.Exists() {
			s, t, _, _ := parseSingJSON(config, host, addTag)
			return nil, nil, s, t, nil
		}
		return nil, nil, nil, nil, nil
	}

	content := bytes.TrimSpace(config)
	if len(content) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("getSing: 内容为空: %w host: %v", ErrJson, host)
	}
	decoded := content
	if looksLikeBase64(string(content)) {
		if d, derr := base64.StdEncoding.DecodeString(string(content)); derr == nil {
			decoded = d
		}
	}
	lines := bytes.Split(bytes.TrimSpace(decoded), []byte{'\n'})
	proxyList := make([]clash.Proxies, 0, len(lines))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		node, perr := convert.ParseURL(string(line))
		if perr != nil {
			continue
		}
		proxyList = append(proxyList, node)
	}
	if len(proxyList) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("getSing: %w host: %v", ErrJson, host)
	}
	return proxyList, nil, nil, nil, nil
}
