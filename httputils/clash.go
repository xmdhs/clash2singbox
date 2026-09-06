package httputils

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/xmdhs/clash2singbox/convert"
	"github.com/xmdhs/clash2singbox/model/clash"
	"golang.org/x/sync/errgroup"
)

var ErrJson = errors.New("错误的格式")

// maxSubBytes 是单个订阅响应体的读取上限。
const maxSubBytes = 10 * 1000 * 1000

// GetClash 抓取订阅并只返回其中的 Clash 节点与分组。
func GetClash(ctx context.Context, hc *http.Client, u string, addTag bool) (clash.Clash, error) {
	c, _, _, err := GetAny(ctx, hc, u, addTag)
	if err != nil {
		return c, fmt.Errorf("GetClash: %w", err)
	}
	return c, nil
}

// GetAny 抓取并解析订阅。u 可以是多个以 | 分隔的地址，也可以是 base64 编码的多行地址列表；
// 每个地址既可以是 http(s) 订阅链接，也可以是单个节点分享链接（如 vmess://）。
// 除 Clash 节点与分组外，还返回订阅内容本身就是 sing-box 配置时提取出的 outbound 及其 tag。
// addTag 为 true 时给所有节点名追加 "[host]"，用于区分多个订阅里的同名节点。
func GetAny(ctx context.Context, hc *http.Client, u string, addTag bool) (clash.Clash, []map[string]any, []string, error) {
	urls := splitSubURLs(u)
	results := make([]subResult, len(urls)) // 按下标写回，保证输出顺序与输入一致
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(3)
	for i, raw := range urls {
		g.Go(func() error {
			res, err := fetchSub(ctx, hc, raw, addTag)
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

	var c clash.Clash
	var singNodes []map[string]any
	var singTags []string
	for _, r := range results {
		c.Proxies = append(c.Proxies, r.proxies...)
		c.ProxyGroup = append(c.ProxyGroup, r.groups...)
		singNodes = append(singNodes, r.singNodes...)
		singTags = append(singTags, r.singTags...)
	}
	return c, singNodes, singTags, nil
}

// splitSubURLs 拆分 sub 参数：按 | 分隔多个地址；只有一个值且为 base64 时，解码后按行拆分。
func splitSubURLs(u string) []string {
	urls := strings.Split(u, "|")
	if len(urls) != 1 {
		return urls
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(u))
	if err != nil {
		return urls
	}
	if lines := nonEmptyLines(decoded); len(lines) > 0 {
		return lines
	}
	return urls
}

// subResult 是单个订阅地址的解析结果。
type subResult struct {
	proxies   []clash.Proxies
	groups    []clash.ProxyGroup
	singNodes []map[string]any // 订阅本身是 sing-box 配置时，其中的节点 outbound
	singTags  []string         // singNodes 中可被分组引用的 tag，不含 shadowtls 这类只作 detour 的节点
}

// fetchSub 抓取并解析单个订阅地址；非 http(s) 的地址直接按节点分享链接解析。
func fetchSub(ctx context.Context, hc *http.Client, raw string, addTag bool) (subResult, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return subResult{}, err
	}
	var res subResult
	if u.Scheme == "http" || u.Scheme == "https" {
		body, err := HttpGet(ctx, hc, raw, maxSubBytes)
		if err != nil {
			return subResult{}, err
		}
		if res, err = parseSubBody(body); err != nil {
			return subResult{}, fmt.Errorf("%s: %w", u.Host, err)
		}
	} else {
		node, err := convert.ParseURL(raw)
		if err != nil {
			return subResult{}, err
		}
		res.proxies = []clash.Proxies{node}
	}
	if addTag {
		res.addHostSuffix(u.Host)
	}
	return res, nil
}

// addHostSuffix 给节点名、分组里的节点引用以及 sing-box outbound 的 tag 追加 "[host]"。
func (r *subResult) addHostSuffix(host string) {
	suffix := "[" + host + "]"
	for i := range r.proxies {
		r.proxies[i].Name += suffix
	}
	for i := range r.groups {
		for j := range r.groups[i].Proxies {
			r.groups[i].Proxies[j] += suffix
		}
	}
	for _, node := range r.singNodes {
		tag, _ := node["tag"].(string)
		node["tag"] = tag + suffix
	}
	for i := range r.singTags {
		r.singTags[i] += suffix
	}
}
