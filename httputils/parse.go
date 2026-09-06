package httputils

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/xmdhs/clash2singbox/convert"
	"github.com/xmdhs/clash2singbox/model/clash"
	"gopkg.in/yaml.v3"
)

// parseSubBody 识别订阅内容的格式并解析：
//  1. 带 outbounds 的 JSON 视为 sing-box 配置，直接提取其中的节点 outbound；
//  2. 其余内容先按 Clash YAML 解析（JSON 是 YAML 的子集，含 proxies 的 JSON 同样适用）；
//  3. 仍没有节点时按节点分享链接列表解析（可整体 base64 编码，每行一个链接）。
//
// 有效但无法识别的 JSON（例如没有 outbounds 的 sing-box 配置）沿用旧行为：视为空订阅，不报错。
func parseSubBody(body []byte) (subResult, error) {
	body = bytes.TrimSpace(body)
	if nodes, tags, ok := parseSingBoxJSON(body); ok {
		return subResult{singNodes: nodes, singTags: tags}, nil
	}
	var c clash.Clash
	if err := yaml.Unmarshal(body, &c); err == nil && len(c.Proxies) > 0 {
		return subResult{proxies: c.Proxies, groups: c.ProxyGroup}, nil
	}
	if gjson.ValidBytes(body) {
		return subResult{}, nil
	}
	proxies, err := parseShareLinks(body)
	if err != nil {
		return subResult{}, err
	}
	return subResult{proxies: proxies}, nil
}

// skipOutboundTypes 是 sing-box 配置里不算节点的 outbound 类型。
var skipOutboundTypes = map[string]bool{
	"direct":   true,
	"block":    true,
	"dns":      true,
	"selector": true,
	"urltest":  true,
}

// parseSingBoxJSON 从 sing-box JSON 配置里提取节点 outbound；body 不是带 outbounds 的 JSON 时 ok 为 false。
// shadowtls 只作为其他节点的 detour 使用，保留 outbound 但不进入 tags。
func parseSingBoxJSON(body []byte) (nodes []map[string]any, tags []string, ok bool) {
	if !gjson.ValidBytes(body) {
		return nil, nil, false
	}
	outbounds := gjson.GetBytes(body, "outbounds")
	if !outbounds.Exists() {
		return nil, nil, false
	}
	for _, o := range outbounds.Array() {
		typ := o.Get("type").String()
		if skipOutboundTypes[typ] {
			continue
		}
		m, isMap := o.Value().(map[string]any)
		if !isMap {
			continue
		}
		nodes = append(nodes, m)
		if typ != "shadowtls" {
			tags = append(tags, o.Get("tag").String())
		}
	}
	return nodes, tags, true
}

// parseShareLinks 解析节点分享链接列表：内容可整体 base64 编码，每行一个链接，无法识别的行跳过。
func parseShareLinks(body []byte) ([]clash.Proxies, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("parseShareLinks: 内容为空: %w", ErrJson)
	}
	if decoded, err := base64.StdEncoding.DecodeString(string(body)); err == nil {
		body = decoded
	}
	var proxies []clash.Proxies
	for _, line := range nonEmptyLines(body) {
		node, err := convert.ParseURL(line)
		if err != nil {
			continue
		}
		proxies = append(proxies, node)
	}
	if len(proxies) == 0 {
		return nil, fmt.Errorf("parseShareLinks: 没有可识别的节点: %w", ErrJson)
	}
	return proxies, nil
}

// nonEmptyLines 按行拆分并去掉每行首尾空白，丢弃空行。
func nonEmptyLines(b []byte) []string {
	var lines []string
	for line := range strings.SplitSeq(string(b), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
