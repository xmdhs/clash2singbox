package httputils

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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

func GetAny(ctx context.Context, hc *http.Client, u string, addTag bool) (clash.Clash, []any, []string, error) {
	urls := strings.Split(u, "|")

	c := clash.Clash{}
	singList := []any{}
	tags := []string{}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(3)

	l := sync.Mutex{}

	for _, v := range urls {
		v := v
		u, err := url.Parse(v)
		if err != nil {
			return c, nil, nil, fmt.Errorf("GetAny: %w", err)
		}
		host := u.Host
		g.Go(func() error {
			b, err := HttpGet(ctx, hc, v, 1000*1000*10)
			if err != nil {
				return err
			}
			lc := clash.Clash{}
			err = yaml.Unmarshal(b, &lc)
			if err != nil || len(lc.Proxies) == 0 {
				s, t, err := getSing(b)
				if err != nil {
					return err
				}
				l.Lock()
				singList = append(singList, s...)
				if addTag {
					t = lo.Map(t, func(item string, index int) string {
						return fmt.Sprintf("%s[%s]", item, host)
					})
				}
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

func getSing(config []byte) ([]any, []string, error) {
	if !gjson.Valid(string(config)) {
		return nil, nil, fmt.Errorf("getSing: %w", ErrJson)
	}

	out := gjson.GetBytes(config, "outbounds").Array()
	outList := make([]any, 0, len(out))
	tagsList := make([]string, 0, len(out))

	for _, v := range out {
		outtype := v.Get("type").String()
		if _, ok := notNeedType[outtype]; ok {
			continue
		}
		if outtype != "shadowtls" {
			tagsList = append(tagsList, v.Get("tag").String())
		}
		outList = append(outList, v.Value())
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
