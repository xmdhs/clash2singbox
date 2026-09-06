package convert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
)

// Patch 把转换结果写进 JSON 模板 b，返回缩进格式的完整配置（命令行版本使用）。
// 模板自带的 outbounds 会保留，其中的 "{all}" 占位符与 filter 规则会被展开；
// include / exclude 是默认 urltest 分组的节点过滤正则；extOut / extags 是订阅直接给出的 sing-box outbound 及其 tag。
func Patch(b []byte, s []singbox.SingBoxOut, eps []*singbox.SingBoxEndpoint, include, exclude string, extOut []any, extags ...string) ([]byte, error) {
	d, err := decodeTemplate(b)
	if err != nil {
		return nil, fmt.Errorf("Patch: %w", err)
	}
	err = patch(d, s, eps, extOut, extags, patchOptions{
		include:      include,
		exclude:      exclude,
		urltest:      true,
		keepTemplate: true,
	})
	if err != nil {
		return nil, fmt.Errorf("Patch: %w", err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "    ")
	if err := enc.Encode(d); err != nil {
		return nil, fmt.Errorf("Patch: %w", err)
	}
	return buf.Bytes(), nil
}

// PatchMap 与 PatchMapFromMap 相同，但接受尚未解码的 JSON 模板。
func PatchMap(tpl []byte, s []singbox.SingBoxOut, eps []*singbox.SingBoxEndpoint, include, exclude string, extOut []any, extags []string, urltestOut bool, outFields bool) (map[string]any, error) {
	d, err := decodeTemplate(tpl)
	if err != nil {
		return nil, fmt.Errorf("PatchMap: %w", err)
	}
	return PatchMapFromMap(d, s, eps, include, exclude, extOut, extags, urltestOut, outFields)
}

// PatchMapFromMap 把转换结果写进已解码的模板 d 并返回它（d 会被就地修改）。
// 模板原有的 outbounds 会被整体替换，需要保留的模板节点应由调用方通过 extOut / extags 传入（clash2sfa 的做法）。
// urltestOut 控制是否生成默认的 select / urltest 分组；
// outFields 控制是否补上 block 与 dns-out 这两个 sing-box 1.11 起废弃的 outbound，只有面向旧版本的模板需要。
func PatchMapFromMap(d map[string]any, s []singbox.SingBoxOut, eps []*singbox.SingBoxEndpoint, include, exclude string, extOut []any, extags []string, urltestOut bool, outFields bool) (map[string]any, error) {
	if d == nil {
		return nil, fmt.Errorf("PatchMap: 配置必须是 JSON 对象")
	}
	err := patch(d, s, eps, extOut, extags, patchOptions{
		include:   include,
		exclude:   exclude,
		urltest:   urltestOut,
		legacyOut: outFields,
	})
	if err != nil {
		return nil, fmt.Errorf("PatchMap: %w", err)
	}
	return d, nil
}

// ToInsecure 让所有节点跳过证书校验。
func ToInsecure(c *clash.Clash) {
	for i := range c.Proxies {
		c.Proxies[i].SkipCertVerify = true
	}
}

func decodeTemplate(tpl []byte) (map[string]any, error) {
	var d map[string]any
	if err := json.Unmarshal(tpl, &d); err != nil {
		return nil, err
	}
	if d == nil {
		return nil, fmt.Errorf("配置必须是 JSON 对象")
	}
	return d, nil
}

// patchOptions 控制 patch 生成哪些内容。
type patchOptions struct {
	include, exclude string // 默认 urltest 分组的节点过滤正则，先 include 再 exclude
	urltest          bool   // 生成默认的 select / urltest 分组
	legacyOut        bool   // 补上 block 与 dns-out
	keepTemplate     bool   // 保留模板原有 outbounds，并展开其中的 {all} 占位符与 filter 规则
}

// patch 把节点 s、endpoint eps 与外部 outbound extOut 合并进模板 d 的 outbounds / endpoints。
func patch(d map[string]any, s []singbox.SingBoxOut, eps []*singbox.SingBoxEndpoint, extOut []any, extags []string, opt patchOptions) error {
	tags := collectTags(s, eps, extags)
	ftags, err := applyIncludeExclude(tags, opt.include, opt.exclude)
	if err != nil {
		return err
	}

	var outbounds []any
	if opt.keepTemplate {
		tpl, _ := d["outbounds"].([]any)
		outbounds = expandTemplateOutbounds(tpl, ftags)
	}
	if opt.urltest && len(ftags) > 0 {
		outbounds = append(outbounds,
			singbox.SingBoxOut{Type: "selector", Tag: "select", Outbounds: append([]string{"urltest"}, tags...), Default: "urltest"},
			singbox.SingBoxOut{Type: "urltest", Tag: "urltest", Outbounds: ftags},
		)
	}
	outbounds = append(outbounds, extOut...)
	for _, v := range s {
		outbounds = append(outbounds, v)
	}
	outbounds = appendIfMissing(outbounds, singbox.SingBoxOut{Type: "direct", Tag: "direct"})
	if opt.legacyOut {
		outbounds = appendIfMissing(outbounds, singbox.SingBoxOut{Type: "block", Tag: "block"})
		outbounds = appendIfMissing(outbounds, singbox.SingBoxOut{Type: "dns", Tag: "dns-out"})
	}
	d["outbounds"] = outbounds

	if len(eps) > 0 {
		existing, _ := d["endpoints"].([]any)
		for _, ep := range eps {
			existing = append(existing, ep)
		}
		d["endpoints"] = existing
	}
	return nil
}

// collectTags 返回可供 select / urltest 引用的全部 tag：普通节点、endpoint 与外部 tag。
func collectTags(s []singbox.SingBoxOut, eps []*singbox.SingBoxEndpoint, extags []string) []string {
	tags := getTags(s)
	for _, ep := range eps {
		if ep != nil && ep.Tag != "" {
			tags = append(tags, ep.Tag)
		}
	}
	return append(tags, extags...)
}

// getTags 返回可被分组引用的节点 tag：跳过只作 detour 的内部节点（Ignored）与只在特定分组可见的节点（Visible）。
func getTags(s []singbox.SingBoxOut) []string {
	tags := make([]string, 0, len(s))
	for _, v := range s {
		if v.Tag != "" && !v.Ignored && len(v.Visible) == 0 {
			tags = append(tags, v.Tag)
		}
	}
	return tags
}

// applyIncludeExclude 先按 include 保留匹配的 tag，再按 exclude 剔除匹配的 tag；空正则表示不过滤。
func applyIncludeExclude(tags []string, include, exclude string) ([]string, error) {
	var err error
	if include != "" {
		if tags, err = filterByRegexp(tags, include, true); err != nil {
			return nil, err
		}
	}
	if exclude != "" {
		if tags, err = filterByRegexp(tags, exclude, false); err != nil {
			return nil, err
		}
	}
	return tags, nil
}

// filterByRegexp 用正则筛选 tags：keepMatch 为 true 保留匹配项，否则保留不匹配项。
func filterByRegexp(tags []string, reg string, keepMatch bool) ([]string, error) {
	re, err := regexp.Compile(reg)
	if err != nil {
		return nil, fmt.Errorf("filter: %w", err)
	}
	return filterFunc(tags, func(tag string) bool { return re.MatchString(tag) == keepMatch }), nil
}

func filterFunc(tags []string, keep func(string) bool) []string {
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		if keep(tag) {
			out = append(out, tag)
		}
	}
	return out
}

// appendIfMissing 在列表里没有同 tag 的 outbound 时追加 o，避免与模板自带的 direct / block 重复。
func appendIfMissing(outbounds []any, o singbox.SingBoxOut) []any {
	for _, item := range outbounds {
		if outboundTag(item) == o.Tag {
			return outbounds
		}
	}
	return append(outbounds, o)
}

// outboundTag 取 outbound 的 tag；outbound 可能是模板解码出的 map，也可能是转换生成的结构体。
func outboundTag(item any) string {
	switch v := item.(type) {
	case map[string]any:
		tag, _ := v["tag"].(string)
		return tag
	case singbox.SingBoxOut:
		return v.Tag
	}
	return ""
}

// expandTemplateOutbounds 处理模板自带的 outbounds：
//   - outbounds 字段里的 "{all}" 占位符替换为全部节点 tag，该 outbound 带 filter 规则时先过滤；
//   - selector 引用了带 filter 的 urltest 时，把该 urltest 过滤出的节点一并追加进 selector，方便手动选择；
//   - 移除 sing-box 不识别的 filter 字段。
func expandTemplateOutbounds(outbounds []any, ftags []string) []any {
	urltestTags := filteredUrltestTags(outbounds, ftags)
	for _, item := range outbounds {
		ob, ok := item.(map[string]any)
		if !ok {
			continue
		}
		switch list := ob["outbounds"].(type) {
		case []any:
			ob["outbounds"] = expandAllPlaceholder(list, ob, ftags, urltestTags)
		case string:
			if list == "{all}" {
				ob["outbounds"] = toAnyList(applyFilter(ob, ftags))
			}
		}
		delete(ob, "filter")
	}
	return outbounds
}

// filteredUrltestTags 收集模板中带 filter 规则的 urltest：tag -> 过滤后的节点 tag。
func filteredUrltestTags(outbounds []any, ftags []string) map[string][]string {
	result := map[string][]string{}
	for _, item := range outbounds {
		ob, ok := item.(map[string]any)
		if !ok || ob["type"] != "urltest" {
			continue
		}
		tag, ok := ob["tag"].(string)
		if _, hasFilter := ob["filter"]; ok && hasFilter {
			result[tag] = applyFilter(ob, ftags)
		}
	}
	return result
}

// expandAllPlaceholder 把 list 中的 "{all}" 替换为（按 ob 的 filter 规则过滤后的）节点 tag；
// ob 是 selector 且引用了带 filter 的 urltest 时，再追加那些 urltest 的节点。
func expandAllPlaceholder(list []any, ob map[string]any, ftags []string, urltestTags map[string][]string) []any {
	out := make([]any, 0, len(list)+len(ftags))
	hasAll := false
	for _, item := range list {
		if item == "{all}" {
			hasAll = true
			continue
		}
		out = append(out, item)
	}
	if hasAll {
		out = append(out, toAnyList(applyFilter(ob, ftags))...)
	}
	if ob["type"] == "selector" {
		for _, item := range out {
			if tag, ok := item.(string); ok {
				out = append(out, toAnyList(urltestTags[tag])...)
			}
		}
	}
	return out
}

func toAnyList(tags []string) []any {
	out := make([]any, len(tags))
	for i, tag := range tags {
		out[i] = tag
	}
	return out
}

// applyFilter 依次应用 outbound 上 filter 字段里的规则，返回过滤后的 tag。规则形如
// {"action": "include" | "exclude", "keywords": "关键词1|关键词2"}。
func applyFilter(ob map[string]any, tags []string) []string {
	rules, _ := ob["filter"].([]any)
	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		action, _ := rule["action"].(string)
		keywords, ok := rule["keywords"].(string)
		if !ok || (action != "include" && action != "exclude") {
			continue
		}
		re, err := regexp.Compile(keywordsPattern(keywords))
		if err != nil {
			continue
		}
		tags = filterFunc(tags, func(tag string) bool { return re.MatchString(tag) == (action == "include") })
	}
	return tags
}

// keywordsPattern 把 "a|b|c" 形式的关键词拼成正则：不含反斜杠的部分按字面量转义，含反斜杠的视为用户写好的正则原样使用。
func keywordsPattern(keywords string) string {
	parts := strings.Split(keywords, "|")
	for i, part := range parts {
		if !strings.Contains(part, `\`) {
			parts[i] = regexp.QuoteMeta(part)
		}
	}
	return strings.Join(parts, "|")
}
