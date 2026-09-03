package httputils

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/samber/lo"
	"github.com/tidwall/gjson"
	"github.com/xmdhs/clash2singbox/convert"
	"github.com/xmdhs/clash2singbox/model/clash"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

func GetClash(ctx context.Context, hc *http.Client, u string, addTag bool) (clash.Clash, error) {
	c, _, _, err := GetAny(ctx, hc, u, addTag)
	if err != nil {
		return c, fmt.Errorf("GetClash: %w", err)
	}
	return c, nil
}

func GetAny(ctx context.Context, hc *http.Client, u string, addTag bool) (clash.Clash, []map[string]any, []string, error) {
	urls := strings.Split(u, "|")

	if len(urls) == 1 {
		u, err := base64.StdEncoding.DecodeString(u)
		if err == nil {
			urls = lo.FilterMap(bytes.Split(u, []byte{'\n'}), func(b []byte, _ int) (string, bool) {
				s := string(b)
				return s, s != ""
			})
		}
	}

	c := clash.Clash{}
	singList := []map[string]any{}
	tags := []string{}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(3)

	l := sync.Mutex{}

	for _, v := range urls {
		u, err := url.Parse(v)
		if err != nil {
			return c, nil, nil, fmt.Errorf("GetAny: %w", err)
		}
		host := u.Host

		g.Go(func() error {
			lc := clash.Clash{}
			if u.Scheme != "http" && u.Scheme != "https" {
				node, err := convert.ParseURL(v)
				if err != nil {
					return err
				}
				lc.Proxies = append(lc.Proxies, node)
			} else {
				b, err := HttpGet(ctx, hc, v, 1000*1000*10)
				if err != nil {
					return err
				}

				// sing-box JSON 不需要先经过 YAML 解析；JSON Clash 配置
				// 仍回退到 YAML，以保持兼容性。
				s, t, validJSON, singJSON := parseSingJSON(b, host, addTag)
				if validJSON && singJSON {
					l.Lock()
					singList = append(singList, s...)
					tags = append(tags, t...)
					l.Unlock()
				} else {
					tc := clash.Clash{}
					err = yaml.Unmarshal(b, &tc)
					if err != nil || len(tc.Proxies) == 0 {
						singNodes, singTags, list, err := getSing(b, host, addTag)
						if err != nil {
							return err
						}
						l.Lock()
						singList = append(singList, singNodes...)
						tags = append(tags, singTags...)
						l.Unlock()
						lc.Proxies = append(lc.Proxies, list...)
					} else {
						lc.Proxies = append(lc.Proxies, tc.Proxies...)
						lc.ProxyGroup = append(lc.ProxyGroup, tc.ProxyGroup...)
					}
				}
			}
			if addTag {
				lc.Proxies = lo.Map(lc.Proxies, func(item clash.Proxies, index int) clash.Proxies {
					item.Name = fmt.Sprintf("%s[%s]", item.Name, host)
					return item
				})
				lc.ProxyGroup = lo.Map(lc.ProxyGroup, func(item clash.ProxyGroup, index int) clash.ProxyGroup {
					item.Proxies = lo.Map(item.Proxies, func(item string, index int) string {
						return fmt.Sprintf("%s[%s]", item, host)
					})
					return item
				})
			}
			l.Lock()
			c.Proxies = append(c.Proxies, lc.Proxies...)
			c.ProxyGroup = append(c.ProxyGroup, lc.ProxyGroup...)
			l.Unlock()
			return nil
		})
	}
	err := g.Wait()
	if err != nil {
		return c, nil, nil, fmt.Errorf("GetAny: %w", err)
	}
	return c, singList, tags, nil
}

var ErrJson = errors.New("错误的格式")

func getSing(config []byte, host string, addTag bool) ([]map[string]any, []string, []clash.Proxies, error) {
	// 首先尝试解析为 JSON 格式的 sing-box 配置。
	singList, tagsList, validJSON, _ := parseSingJSON(config, host, addTag)
	if validJSON {
		return singList, tagsList, nil, nil
	}

	// 如果不是 JSON，尝试解析为订阅链接格式
	// 订阅链接通常是 Base64 编码的，每行一个节点链接
	content := bytes.TrimSpace(config)
	if len(content) == 0 {
		return nil, nil, nil, fmt.Errorf("getSing: 内容为空: %w host: %v", ErrJson, host)
	}

	// 尝试 Base64 解码
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(content)))
	n, err := base64.StdEncoding.Decode(decoded, content)
	if err != nil {
		// 如果 Base64 解码失败，可能是已经解码过的内容，直接处理
		decoded = content
	} else {
		decoded = decoded[:n]
	}

	// 按行分割，处理每个节点链接
	lines := bytes.Split(bytes.TrimSpace(decoded), []byte{'\n'})
	proxyList := make([]clash.Proxies, 0)

	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		// 解析节点链接并转换为 sing-box 格式
		node, err := convert.ParseURL(string(line))
		if err != nil {
			continue // 跳过无法解析的节点
		}
		proxyList = append(proxyList, node)
	}

	if len(proxyList) == 0 {
		return nil, nil, nil, fmt.Errorf("getSing: %w host: %v", ErrJson, host)
	}

	return nil, nil, proxyList, nil
}

// parseSingJSON 负责校验并提取 JSON 文档，并返回文档是否有效以及是否
// 应由 GetAny 作为 sing-box 配置处理。含有实际 proxies 的 JSON Clash
// 配置返回 singJSON=false，让调用方继续使用 YAML 解码。
func parseSingJSON(config []byte, host string, addTag bool) (
	outList []map[string]any,
	tagsList []string,
	validJSON bool,
	singJSON bool,
) {
	trimmed := bytes.TrimSpace(config)
	if len(trimmed) == 0 || !gjson.ValidBytes(trimmed) {
		return nil, nil, false, false
	}

	outs := gjson.GetBytes(trimmed, "outbounds")
	if !outs.Exists() {
		// 只有在不存在 outbounds 时才检查 proxies，避免为标准
		// sing-box JSON 再做一次全量路径扫描。
		proxies := gjson.GetBytes(trimmed, "proxies")
		if len(proxies.Array()) > 0 {
			return nil, nil, true, false
		}
		// 与原来的 gjson.Valid 行为一致：有效 JSON 但没有可用
		// outbound 时不再回退到逐行订阅解析。
		return nil, nil, true, true
	}

	out := outs.Array()
	outList = make([]map[string]any, 0, len(out))
	tagsList = make([]string, 0, len(out))
	for _, v := range out {
		outtype := v.Get("type").String()
		if _, ok := notNeedType[outtype]; ok {
			continue
		}
		m, ok := v.Value().(map[string]any)
		if !ok {
			continue
		}
		tag := v.Get("tag").String()
		if addTag {
			tag = fmt.Sprintf("%s[%s]", tag, host)
			m["tag"] = tag
		}
		outList = append(outList, m)
		if outtype != "shadowtls" {
			tagsList = append(tagsList, tag)
		}
	}
	return outList, tagsList, true, true
}

var notNeedType = map[string]struct{}{
	"direct":   {},
	"block":    {},
	"dns":      {},
	"selector": {},
	"urltest":  {},
}
