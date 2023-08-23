package httputils

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/xmdhs/clash2singbox/model/clash"
	"gopkg.in/yaml.v3"
)

func GetClash(cxt context.Context, hc *http.Client, url string) (clash.Clash, error) {
	urls := strings.Split(url, "|")

	c := clash.Clash{}

	for _, v := range urls {
		b, err := HttpGet(cxt, hc, v, 1000*1000*10)
		if err != nil {
			return c, fmt.Errorf("GetClash: %w", err)
		}
		lc := clash.Clash{}
		err = yaml.Unmarshal(b, &lc)
		if err != nil {
			return c, fmt.Errorf("GetClash: %w", err)
		}
		c.Proxies = append(c.Proxies, lc.Proxies...)
	}
	return c, nil
}
