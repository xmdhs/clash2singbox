package convert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/xmdhs/clash2singbox/clash"
	"github.com/xmdhs/clash2singbox/singbox"
)

func filter(isinclude bool, reg string, sl []string) []string {
	r := regexp.MustCompile(reg)
	return getForList(sl, func(v string) (string, bool) {
		has := r.MatchString(v)
		if has && isinclude {
			return v, true
		}
		if !isinclude && !has {
			return v, true
		}
		return "", false
	})
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

func getServers(s []singbox.SingBoxOut) []string {
	m := map[string]struct{}{}
	return getForList(s, func(v singbox.SingBoxOut) (string, bool) {
		server := v.Server
		_, has := m[server]
		if server == "" || has {
			return "", false
		}
		m[server] = struct{}{}
		return server, true
	})
}

func getTags(s []singbox.SingBoxOut) []string {
	return getForList(s, func(v singbox.SingBoxOut) (string, bool) {
		tag := v.Tag
		if tag == "" {
			return "", false
		}
		return tag, true
	})
}

func Patch(b []byte, s []singbox.SingBoxOut, include, exclude string) ([]byte, error) {
	d := map[string]interface{}{}
	err := json.Unmarshal(b, &d)
	if err != nil {
		return nil, fmt.Errorf("patch: %w", err)
	}
	servers := getServers(s)
	tags := getTags(s)

	ftags := tags
	if include != "" {
		ftags = filter(true, include, ftags)
	}
	if exclude != "" {
		ftags = filter(false, exclude, ftags)
	}

	d["dns"].(map[string]interface{})["rules"] = []map[string]interface{}{
		{
			"server":     "remote",
			"clash_mode": "global",
		},
		{
			"clash_mode": "direct",
			"server":     "local",
		},
		{
			"geosite": "cn",
			"server":  "local",
			"domain":  servers,
		},
	}

	s = append([]singbox.SingBoxOut{{
		Type:      "selector",
		Tag:       "select",
		Outbounds: append([]string{"urltest"}, tags...),
		Default:   "urltest",
	}}, s...)

	s = append(s, singbox.SingBoxOut{
		Type: "direct",
		Tag:  "direct",
	})
	s = append(s, singbox.SingBoxOut{
		Type: "block",
		Tag:  "block",
	})
	s = append(s, singbox.SingBoxOut{
		Type: "dns",
		Tag:  "dns-out",
	})
	s = append(s, singbox.SingBoxOut{
		Type:      "urltest",
		Tag:       "urltest",
		Outbounds: ftags,
	})

	d["outbounds"] = s

	bw := &bytes.Buffer{}
	jw := json.NewEncoder(bw)
	jw.SetIndent("", "    ")
	err = jw.Encode(d)
	if err != nil {
		return nil, fmt.Errorf("patch: %w", err)
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
