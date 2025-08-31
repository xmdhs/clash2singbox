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

func filter(isinclude bool, reg string, sl []string) ([]string, error) {
	r, err := regexp.Compile(reg)
	if err != nil {
		return sl, fmt.Errorf("filter: %w", err)
	}
	return getForList(sl, func(v string) (string, bool) {
		has := r.MatchString(v)
		if has && isinclude {
			return v, true
		}
		if !isinclude && !has {
			return v, true
		}
		return "", false
	}), nil
}

func getForList[K, V any](l []K, check func(K) (V, bool)) []V {
	sl := make([]V, 0, len(l))
	for _, v := range l {
		s, ok := check(v)
		if !ok {
			continue
		}
		sl = append(sl, s)
	}
	return sl
}

// func getServers(s []singbox.SingBoxOut) []string {
// 	m := map[string]struct{}{}
// 	return getForList(s, func(v singbox.SingBoxOut) (string, bool) {
// 		server := v.Server
// 		_, has := m[server]
// 		if server == "" || has {
// 			return "", false
// 		}
// 		m[server] = struct{}{}
// 		return server, true
// 	})
// }

func getTags(s []singbox.SingBoxOut) []string {
	return getForList(s, func(v singbox.SingBoxOut) (string, bool) {
		tag := v.Tag
		if tag == "" || v.Ignored || len(v.Visible) != 0 {
			return "", false
		}
		return tag, true
	})
}

func Patch(b []byte, s []singbox.SingBoxOut, include, exclude string, extOut []any, extags ...string) ([]byte, error) {
	d, err := patchMap(b, s, include, exclude, extOut, extags, true, true)
	if err != nil {
		return nil, fmt.Errorf("Patch: %w", err)
	}
	bw := &bytes.Buffer{}
	jw := json.NewEncoder(bw)
	jw.SetIndent("", "    ")
	err = jw.Encode(d)
	if err != nil {
		return nil, fmt.Errorf("Patch: %w", err)
	}
	return bw.Bytes(), nil
}

func ToInsecure(c *clash.Clash) {
	for i := range c.Proxies {
		p := c.Proxies[i]
		p.SkipCertVerify = true
		c.Proxies[i] = p
	}
}

func patchMap(
	tpl []byte,
	s []singbox.SingBoxOut,
	include, exclude string,
	extOut []any,
	extags []string,
	urltestOut bool,
	outFields bool,
) (map[string]any, error) {
	d := map[string]any{}
	err := json.Unmarshal(tpl, &d)
	if err != nil {
		return nil, fmt.Errorf("PatchMap: %w", err)
	}
	tags := getTags(s)

	tags = append(tags, extags...)

	ftags := tags
	if exclude != "" {
		ftags, err = filter(false, exclude, ftags)
		if err != nil {
			return nil, fmt.Errorf("PatchMap: %w", err)
		}
	}
	if include != "" {
		ftags, err = filter(true, include, ftags)
		if err != nil {
			return nil, fmt.Errorf("PatchMap: %w", err)
		}
	}

	anyList := make([]any, 0, len(s)+len(extOut)+5)

	if urltestOut && len(ftags) > 0 {
		anyList = append(anyList, singbox.SingBoxOut{
			Type:      "selector",
			Tag:       "select",
			Outbounds: append([]string{"urltest"}, tags...),
			Default:   "urltest",
		})
		anyList = append(anyList, singbox.SingBoxOut{
			Type:      "urltest",
			Tag:       "urltest",
			Outbounds: ftags,
		})
	}

	anyList = append(anyList, extOut...)
	for _, v := range s {
		anyList = append(anyList, v)
	}

	// 检查模板中是否已经存在这些特殊outbound，避免重复添加
	templateTags := make(map[string]bool)
	if outboundsRaw, exists := d["outbounds"]; exists {
		if outboundsSlice, ok := outboundsRaw.([]any); ok {
			for _, outbound := range outboundsSlice {
				if outboundMap, ok := outbound.(map[string]any); ok {
					if tag, exists := outboundMap["tag"]; exists {
						if tagStr, ok := tag.(string); ok {
							templateTags[tagStr] = true
						}
					}
				}
			}
		}
	}

	// 只有当模板中不存在时才添加默认的outbound
	if !templateTags["direct"] {
		anyList = append(anyList, singbox.SingBoxOut{
			Type: "direct",
			Tag:  "direct",
		})
	}

	if outFields {
		if !templateTags["block"] {
			anyList = append(anyList, singbox.SingBoxOut{
				Type: "block",
				Tag:  "block",
			})
		}
		// DNS 类型的 outbound 在 sing-box 1.11.0 中已被废弃，不再添加
	}

	// 处理模板中的outbounds，先替换{all}占位符，然后应用filter并移除filter字段
	var templateOutbounds []any
	if outboundsRaw, exists := d["outbounds"]; exists {
		if outboundsSlice, ok := outboundsRaw.([]any); ok {
			templateOutbounds = make([]any, len(outboundsSlice))

			// 第一步：收集所有 urltest 节点及其 filter 信息
			urltestFilters := make(map[string][]string) // tag -> filtered tags
			for _, outbound := range outboundsSlice {
				if outboundMap, ok := outbound.(map[string]any); ok {
					if outboundType, hasType := outboundMap["type"].(string); hasType && outboundType == "urltest" {
						if tag, hasTag := outboundMap["tag"].(string); hasTag {
							if _, hasFilter := outboundMap["filter"]; hasFilter {
								filteredTags := applyFilter(outbound, ftags)
								urltestFilters[tag] = filteredTags
							}
						}
					}
				}
			}

			// 第二步：处理所有 outbound
			for i, outbound := range outboundsSlice {
				outboundMap, ok := outbound.(map[string]any)
				if ok {
					// 首先处理 {all} 占位符替换（无论是否有filter字段）
					if outboundOutbounds, hasOutbounds := outboundMap["outbounds"]; hasOutbounds {
						// 处理数组形式的outbounds
						if outboundOutboundsSlice, ok := outboundOutbounds.([]any); ok {
							needsReplacement := false
							newOutbounds := make([]any, 0, len(outboundOutboundsSlice))

							// 先收集所有非{all}的现有项
							for _, item := range outboundOutboundsSlice {
								if allStr, ok := item.(string); ok && allStr == "{all}" {
									needsReplacement = true
									// {all}会在后面处理
								} else {
									newOutbounds = append(newOutbounds, item)
								}
							}

							// 如果需要替换{all}
							if needsReplacement {
								// 如果有filter字段，使用过滤后的标签，否则使用所有标签
								tagsToUse := ftags
								if _, hasFilter := outboundMap["filter"]; hasFilter {
									filteredTags := applyFilter(outbound, ftags)
									tagsToUse = filteredTags
								}

								// 将过滤后的标签添加到newOutbounds中
								for _, tag := range tagsToUse {
									newOutbounds = append(newOutbounds, tag)
								}
							}

							// 特殊处理：如果这是一个 selector 类型且包含自动选择节点，需要追加对应的具体节点
							if outboundType, hasType := outboundMap["type"].(string); hasType && outboundType == "selector" {
								for _, item := range newOutbounds {
									if itemStr, ok := item.(string); ok {
										// 检查是否有对应的 urltest 节点
										if filteredTags, exists := urltestFilters[itemStr]; exists {
											// 追加对应的具体节点
											for _, tag := range filteredTags {
												newOutbounds = append(newOutbounds, tag)
											}
										}
									}
								}
							}

							if needsReplacement || len(newOutbounds) != len(outboundOutboundsSlice) {
								outboundMap["outbounds"] = newOutbounds
							}
						} else if outboundOutboundsStr, ok := outboundOutbounds.(string); ok && outboundOutboundsStr == "{all}" {
							// 处理字符串形式的{all}
							tagsToUse := ftags
							if _, hasFilter := outboundMap["filter"]; hasFilter {
								filteredTags := applyFilter(outbound, ftags)
								tagsToUse = filteredTags
							}

							// 将字符串形式的{all}替换为标签数组
							stringTags := make([]any, len(tagsToUse))
							for i, tag := range tagsToUse {
								stringTags[i] = tag
							}
							outboundMap["outbounds"] = stringTags
						}
					}
				}

				// 移除filter字段
				templateOutbounds[i] = removeFilterField(outbound)
			}
		}
	}

	// 将模板outbounds和生成的outbounds合并
	finalOutbounds := append(templateOutbounds, anyList...)
	d["outbounds"] = finalOutbounds

	return d, nil
}

func PatchMap(
	tpl []byte,
	s []singbox.SingBoxOut,
	include, exclude string,
	extOut []any,
	extags []string,
	urltestOut bool,
	outFields bool,
) (map[string]any, error) {
	d := map[string]any{}
	err := json.Unmarshal(tpl, &d)
	if err != nil {
		return nil, fmt.Errorf("PatchMap: %w", err)
	}
	tags := getTags(s)

	tags = append(tags, extags...)

	ftags := tags
	if include != "" {
		ftags, err = filter(true, include, ftags)
		if err != nil {
			return nil, fmt.Errorf("PatchMap: %w", err)
		}
	}
	if exclude != "" {
		ftags, err = filter(false, exclude, ftags)
		if err != nil {
			return nil, fmt.Errorf("PatchMap: %w", err)
		}
	}

	anyList := make([]any, 0, len(s)+len(extOut)+5)

	if urltestOut {
		anyList = append(anyList, singbox.SingBoxOut{
			Type:      "selector",
			Tag:       "select",
			Outbounds: append([]string{"urltest"}, tags...),
			Default:   "urltest",
		})
		anyList = append(anyList, singbox.SingBoxOut{
			Type:      "urltest",
			Tag:       "urltest",
			Outbounds: ftags,
		})
	}

	anyList = append(anyList, extOut...)
	for _, v := range s {
		anyList = append(anyList, v)
	}

	anyList = append(anyList, singbox.SingBoxOut{
		Type: "direct",
		Tag:  "direct",
	})

	if outFields {
		anyList = append(anyList, singbox.SingBoxOut{
			Type: "block",
			Tag:  "block",
		})
		anyList = append(anyList, singbox.SingBoxOut{
			Type: "dns",
			Tag:  "dns-out",
		})
	}

	d["outbounds"] = anyList

	return d, nil
}

// applyFilter 应用过滤规则到节点列表
func applyFilter(outbound any, allTags []string) []string {
	// 将any转换为map[string]any进行处理
	outboundMap, ok := outbound.(map[string]any)
	if !ok {
		return allTags
	}

	// 检查是否有filter字段
	filterRaw, hasFilter := outboundMap["filter"]
	if !hasFilter {
		return allTags
	}

	// 解析filter规则
	filterRules, ok := filterRaw.([]any)
	if !ok {
		return allTags
	}

	filteredTags := allTags

	// 应用每个filter规则
	for _, ruleRaw := range filterRules {
		ruleMap, ok := ruleRaw.(map[string]any)
		if !ok {
			continue
		}

		actionRaw, hasAction := ruleMap["action"]
		keywordsRaw, hasKeywords := ruleMap["keywords"]
		if !hasAction || !hasKeywords {
			continue
		}

		action, ok := actionRaw.(string)
		if !ok {
			continue
		}

		keywords, ok := keywordsRaw.(string)
		if !ok {
			continue
		}

		// 改进正则表达式构建 - 转义特殊字符并正确处理分隔符
		keywordParts := strings.Split(keywords, "|")
		var escapedParts []string
		for _, part := range keywordParts {
			// 转义正则表达式特殊字符，但保留原有的意图
			escapedPart := regexp.QuoteMeta(part)
			// 如果原来就是正则表达式，去掉不必要的转义
			if strings.Contains(part, "\\") {
				escapedPart = part
			}
			escapedParts = append(escapedParts, escapedPart)
		}
		pattern := strings.Join(escapedParts, "|")

		r, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}

		// 根据action应用过滤
		switch action {
		case "include":
			filteredTags = getForList(filteredTags, func(tag string) (string, bool) {
				matches := r.MatchString(tag)
				if matches {
					return tag, true
				}
				return "", false
			})
		case "exclude":
			filteredTags = getForList(filteredTags, func(tag string) (string, bool) {
				matches := r.MatchString(tag)
				if !matches {
					return tag, true
				}
				return "", false
			})
		}
	}

	return filteredTags
}

// removeFilterField 从outbound配置中移除filter字段
func removeFilterField(outbound any) any {
	outboundMap, ok := outbound.(map[string]any)
	if !ok {
		return outbound
	}

	// 删除filter字段
	delete(outboundMap, "filter")
	return outboundMap
}
