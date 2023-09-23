package httputils

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/samber/lo"
	"github.com/xmdhs/clash2singbox/model/clash"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

func GetClash(ctx context.Context, hc *http.Client, u string, addTag bool) (clash.Clash, error) {
	urls := strings.Split(u, "|")

	c := clash.Clash{}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(3)

	l := sync.Mutex{}

	for _, v := range urls {
		v := v
		u, err := url.Parse(v)
		if err != nil {
			return c, fmt.Errorf("GetClash: %w", err)
		}
		host := u.Host
		g.Go(func() error {
			b, err := HttpGet(ctx, hc, v, 1000*1000*10)
			if err != nil {
				return err
			}
			lc := clash.Clash{}
			err = yaml.Unmarshal(b, &lc)
			if err != nil {
				return err
			}
			if addTag {
				lc.Proxies = lo.Map(lc.Proxies, func(item clash.Proxies, index int) clash.Proxies {
					item.Name = fmt.Sprintf("[%s]%s", item.Name, host)
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
		return c, fmt.Errorf("GetClash: %w", err)
	}
	return c, nil
}
