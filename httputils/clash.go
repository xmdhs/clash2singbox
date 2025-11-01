package httputils

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/samber/lo"
	"github.com/tidwall/gjson"
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
		if u.Scheme != "http" && u.Scheme != "https" {
			node, err := parseNodeLink(v)
			if err != nil {
				return c, nil, nil, fmt.Errorf("GetAny: %w", err)
			}
			if tag, ok := node["tag"].(string); ok {
				l.Lock()
				singList = append(singList, node)
				tags = append(tags, tag)
				l.Unlock()
			}
			continue
		}

		g.Go(func() error {
			b, err := HttpGet(ctx, hc, v, 1000*1000*10)
			if err != nil {
				return err
			}
			lc := clash.Clash{}
			err = yaml.Unmarshal(b, &lc)
			if err != nil || len(lc.Proxies) == 0 {
				h := ""
				if addTag {
					h = host
				}
				s, t, err := getSing(b, h)
				if err != nil {
					return err
				}
				l.Lock()
				singList = append(singList, s...)
				tags = append(tags, t...)
				l.Unlock()
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

func getSing(config []byte, host string) ([]map[string]any, []string, error) {
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
				if host != "" {
					tag = fmt.Sprintf("%s[%s]", tag, host)
					m["tag"] = tag
				}
				outList = append(outList, m)
				if outtype != "shadowtls" {
					tagsList = append(tagsList, tag)
				}
			}
		}
		return outList, tagsList, nil
	}

	// 如果不是 JSON，尝试解析为订阅链接格式
	// 订阅链接通常是 Base64 编码的，每行一个节点链接
	content := strings.TrimSpace(string(config))
	if content == "" {
		return nil, nil, fmt.Errorf("getSing: 内容为空: %w host: %v", ErrJson, host)
	}

	// 尝试 Base64 解码
	decoded, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		// 如果 Base64 解码失败，可能是已经解码过的内容，直接处理
		decoded = config
	}

	// 按行分割，处理每个节点链接
	lines := strings.Split(strings.TrimSpace(string(decoded)), "\n")
	outList := make([]map[string]any, 0)
	tagsList := make([]string, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 解析节点链接并转换为 sing-box 格式
		node, err := parseNodeLink(line)
		if err != nil {
			continue // 跳过无法解析的节点
		}

		// 添加主机标签
		if host != "" {
			if tag, ok := node["tag"].(string); ok {
				node["tag"] = fmt.Sprintf("%s[%s]", tag, host)
			}
		}

		outList = append(outList, node)
		if tag, ok := node["tag"].(string); ok {
			tagsList = append(tagsList, tag)
		}
	}

	if len(outList) == 0 {
		return nil, nil, fmt.Errorf("getSing: %w host: %v", ErrJson, host)
	}

	return outList, tagsList, nil
}

var notNeedType = map[string]struct{}{
	"direct":   {},
	"block":    {},
	"dns":      {},
	"selector": {},
	"urltest":  {},
}

// parseNodeLink 解析节点链接并转换为 sing-box outbound 格式
func parseNodeLink(link string) (map[string]any, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "trojan":
		return parseTrojanLink(u)
	case "vmess":
		return parseVmessLink(u)
	case "vless":
		return parseVlessLink(u)
	case "ss":
		return parseShadowsocksLink(u)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", u.Scheme)
	}
}

// parseTrojanLink 解析 Trojan 链接
func parseTrojanLink(u *url.URL) (map[string]any, error) {
	password := u.User.Username()
	host := u.Hostname()
	port := u.Port()

	node := map[string]any{
		"type":        "trojan",
		"tag":         getNameFromURL(u),
		"server":      host,
		"server_port": parsePort(port),
		"password":    password,
		"network":     []string{"tcp", "udp"}, // trojan协议支持TCP和UDP
	}

	// 解析查询参数
	query := u.Query()

	// 处理TLS配置
	tls := map[string]any{
		"enabled": true,
	}

	// 设置SNI
	if sni := query.Get("sni"); sni != "" {
		tls["server_name"] = sni
	} else {
		// 如果没有SNI，使用host作为server_name
		tls["server_name"] = host
	}

	// 处理peer参数（可能用于TLS验证）
	if peer := query.Get("peer"); peer != "" {
		// peer参数通常用于指定证书验证的主机名
		tls["server_name"] = peer
	}

	node["tls"] = tls

	return node, nil
}

// parseVmessLink 解析 Vmess 链接
func parseVmessLink(u *url.URL) (map[string]any, error) {
	// Vmess 链接通常是 Base64 编码的 JSON，需要额外处理
	return nil, fmt.Errorf("vmess parsing not implemented yet")
}

// parseVlessLink 解析 Vless 链接
func parseVlessLink(u *url.URL) (map[string]any, error) {
	uuid := u.User.Username()
	host := u.Hostname()
	port := u.Port()

	node := map[string]any{
		"type":        "vless",
		"tag":         getNameFromURL(u),
		"server":      host,
		"server_port": parsePort(port),
		"uuid":        uuid,
		"network":     []string{"tcp", "udp"}, // vless协议支持TCP和UDP
	}

	// 解析查询参数
	query := u.Query()
	if sni := query.Get("sni"); sni != "" {
		node["tls"] = map[string]any{
			"enabled":     true,
			"server_name": sni,
		}
	}

	return node, nil
}

// parseShadowsocksLink 解析 Shadowsocks 链接
func parseShadowsocksLink(u *url.URL) (map[string]any, error) {
	host := u.Hostname()
	port := u.Port()

	// Shadowsocks 链接的格式: ss://base64(method:password)@host:port#name
	userInfo, err := base64.StdEncoding.DecodeString(u.User.String())
	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(string(userInfo), ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid shadowsocks user info")
	}

	method := parts[0]
	password := parts[1]

	node := map[string]any{
		"type":        "shadowsocks",
		"tag":         getNameFromURL(u),
		"server":      host,
		"server_port": parsePort(port),
		"method":      method,
		"password":    password,
		"network":     []string{"tcp", "udp"}, // shadowsocks协议支持TCP和UDP
	}

	return node, nil
}

// getNameFromURL 从 URL 中提取节点名称
func getNameFromURL(u *url.URL) string {
	if u.Fragment != "" {
		// URL 解码片段部分
		if name, err := url.QueryUnescape(u.Fragment); err == nil {
			return name
		}
		return u.Fragment
	}
	// 如果没有片段，使用主机名作为名称
	return u.Hostname()
}

// parsePort 解析端口字符串为整数
func parsePort(portStr string) int {
	if portStr == "" {
		return 443 // 默认端口
	}

	// 使用strconv.Atoi进行更可靠的转换
	if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port <= 65535 {
		return port
	}

	// 如果转换失败，返回默认端口
	return 443
}
