package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/xmdhs/clash2singbox/clash"
	"github.com/xmdhs/clash2singbox/convert"
	"github.com/xmdhs/clash2singbox/httputils"
	"github.com/xmdhs/clash2singbox/singbox"
	"gopkg.in/yaml.v3"
)

var (
	url     string
	path    string
	outPath string
)

//go:embed config.json.template
var configByte []byte

func init() {
	flag.StringVar(&url, "url", "", "订阅地址")
	flag.StringVar(&path, "i", "", "本地 clash 文件")
	flag.StringVar(&outPath, "o", "config.json", "输出文件")
	flag.Parse()
}

func main() {
	var b []byte
	var err error
	if url != "" {
		b, err = httputils.HttpGet(url)
	} else if path != "" {
		b, err = os.ReadFile(path)
	} else {
		panic("url 和 i 参数不能都为空")
	}
	if err != nil {
		panic(err)
	}

	c := clash.Clash{}
	err = yaml.Unmarshal(b, &c)
	if err != nil {
		panic(err)
	}
	s, err := convert.Clash2sing(c)
	if err != nil {
		panic(err)
	}
	outb, err := os.ReadFile(outPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			outb = configByte
		} else {
			panic(err)
		}
	}

	outb, err = patch(outb, s)
	if err != nil {
		panic(err)
	}

	os.WriteFile(outPath, outb, 0777)
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

func patch(b []byte, s []singbox.SingBoxOut) ([]byte, error) {
	d := map[string]interface{}{}
	err := json.Unmarshal(b, &d)
	if err != nil {
		return nil, fmt.Errorf("patch: %w", err)
	}
	servers := getServers(s)
	tags := getTags(s)

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
		Outbounds: tags,
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
