package httputils

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/tidwall/gjson"
	"github.com/xmdhs/clash2singbox/model/clash"
	"golang.org/x/sync/errgroup"
)

func GetClash(ctx context.Context, hc *http.Client, u string, addTag bool) (clash.Clash, error) {
	c, _, _, err := GetAny(ctx, hc, u, addTag)
	if err != nil {
		return c, fmt.Errorf("GetClash: %w", err)
	}
	return c, nil
}

func GetAny(ctx context.Context, hc *http.Client, u string, addTag bool) (clash.Clash, []map[string]any, []string, error) {
	urls := splitSubURLs(u)

	// 单 URL 快路径：跳过 errgroup/Mutex，直接同步抓取解析。
	if len(urls) == 1 {
		parsed, err := url.Parse(urls[0])
		if err != nil {
			return clash.Clash{}, nil, nil, fmt.Errorf("GetAny: %w", err)
		}
		res, err := fetchOneURL(ctx, hc, urls[0], parsed.Host, addTag, 0)
		if err != nil {
			return clash.Clash{}, nil, nil, fmt.Errorf("GetAny: %w", err)
		}
		return clash.Clash{Proxies: res.proxies, ProxyGroup: res.groups}, res.singNodes, res.singTags, nil
	}

	// 多 URL：按输入下标写回以保序（原并发 append 顺序随机，导致输出 diff 巨大）。
	results := make([]subResult, len(urls))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(3)

	for i, v := range urls {
		parsed, err := url.Parse(v)
		if err != nil {
			return clash.Clash{}, nil, nil, fmt.Errorf("GetAny: %w", err)
		}
		host := parsed.Host
		g.Go(func() error {
			res, err := fetchOneURL(ctx, hc, v, host, addTag, i)
			if err != nil {
				return err
			}
			results[i] = res
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return clash.Clash{}, nil, nil, fmt.Errorf("GetAny: %w", err)
	}
	c := clash.Clash{}
	var singList []map[string]any
	var tags []string
	for _, res := range results {
		c.Proxies = append(c.Proxies, res.proxies...)
		c.ProxyGroup = append(c.ProxyGroup, res.groups...)
		singList = append(singList, res.singNodes...)
		tags = append(tags, res.singTags...)
	}
	return c, singList, tags, nil
}

var ErrJson = errors.New("错误的格式")

func getSing(config []byte, host string, addTag bool) ([]map[string]any, []string, []clash.Proxies, error) {
	proxies, _, singList, singTags, err := getSingParts(config, host, addTag)
	if err != nil {
		return nil, nil, nil, err
	}
	return singList, singTags, proxies, nil
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
			tag = tag + "[" + host + "]"
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
