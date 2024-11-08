package convert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"

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

func Patch(b []byte, s []singbox.SingBoxOut, include, exclude string, extOut []interface{}, extags ...string) ([]byte, error) {
	d, err := PatchMap(b, s, include, exclude, extOut, extags, true, true)
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

func PatchMap(
	tpl []byte,
	s []singbox.SingBoxOut,
	include, exclude string,
	extOut []interface{},
	extags []string,
	urltestOut bool,
	outFields bool,
) (map[string]any, error) {
	d := map[string]interface{}{}
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
