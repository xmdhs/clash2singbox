package httputils

import (
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
					return fmt.Errorf("GetAny: %w", err)
				}
				lc.Proxies = append(c.Proxies, node)
			} else {
				b, err := HttpGet(ctx, hc, v, 1000*1000*10)
				if err != nil {
					return err
				}
				tc := clash.Clash{}
				err = yaml.Unmarshal(b, &tc)
				if err != nil || len(tc.Proxies) == 0 {
					s, t, list, err := getSing(b, host, addTag)
					if err != nil {
						return err
					}
					l.Lock()
					singList = append(singList, s...)
					tags = append(tags, t...)
					l.Unlock()
					lc.Proxies = append(lc.Proxies, list...)
				} else {
					lc.Proxies = append(lc.Proxies, tc.Proxies...)
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
			defer l.Unlock()
			c.Proxies = append(c.Proxies, lc.Proxies...)
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
	// 首先尝试解析为 JSON 格式的 sing-box 配置
	if gjson.Valid(string(config)) {
		out := gjson.GetBytes(config, "outbounds").Array()
		outList := make([]map[string]any, 0, len(out))
		tagsList := make([]string, 0, len(out))

		for _, v := range out {
			outtype := v.Get("type").String()
			if _, ok := notNeedType[outtype]; ok {
				continue
			}
			m, ok := v.Value().(map[string]any)
			if ok {
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
		}
		return outList, tagsList, nil, nil
	}

	// 如果不是 JSON，尝试解析为订阅链接格式
	// 订阅链接通常是 Base64 编码的，每行一个节点链接
	content := strings.TrimSpace(string(config))
	if content == "" {
		return nil, nil, nil, fmt.Errorf("getSing: 内容为空: %w host: %v", ErrJson, host)
	}

	// 尝试 Base64 解码
	decoded, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		// 如果 Base64 解码失败，可能是已经解码过的内容，直接处理
		decoded = config
	}

	// 按行分割，处理每个节点链接
	lines := strings.Split(strings.TrimSpace(string(decoded)), "\n")
	outList := make([]clash.Proxies, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// 解析节点链接并转换为 sing-box 格式
		node, err := convert.ParseURL(line)
		if err != nil {
			continue // 跳过无法解析的节点
		}
		outList = append(outList, node)
	}

	if len(outList) == 0 {
		return nil, nil, nil, fmt.Errorf("getSing: %w host: %v", ErrJson, host)
	}

	return nil, nil, outList, nil
}

var notNeedType = map[string]struct{}{
	"direct":   {},
	"block":    {},
	"dns":      {},
	"selector": {},
	"urltest":  {},
}
