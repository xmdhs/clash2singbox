package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/xmdhs/clash2singbox/convert"
	"github.com/xmdhs/clash2singbox/httputils"
	"github.com/xmdhs/clash2singbox/model"
	"github.com/xmdhs/clash2singbox/model/clash"
	"gopkg.in/yaml.v3"
)

var (
	url      string
	path     string
	outPath  string
	template string
	include  string
	exclude  string
	insecure bool
	ignore   bool
)

//go:embed config.json.template
var configByte []byte

func init() {
	flag.StringVar(&url, "url", "", "订阅地址，多个链接使用 | 分割")
	flag.StringVar(&path, "i", "", "本地 clash 文件")
	flag.StringVar(&outPath, "o", "config.json", "输出文件")
	flag.StringVar(&template, "template", "config.json", "模板文件")
	flag.StringVar(&include, "include", "", "urltest 选择的节点")
	flag.StringVar(&exclude, "exclude", "", "urltest 排除的节点")
	flag.BoolVar(&insecure, "insecure", false, "所有节点不验证证书")
	flag.BoolVar(&ignore, "ignore", true, "忽略无法转换的节点")
	// 不在此处 flag.Parse()，否则与 go test 的 flag 冲突
}

func main() {
	flag.Parse()
	run(url, path, outPath, template, include, exclude, insecure)
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

func run(url, path, outPath, template, include, exclude string, insecure bool) {
	var c clash.Clash
	var singNodes []map[string]any
	var singTags []string
	switch {
	case url != "":
		var err error
		c, singNodes, singTags, err = httputils.GetAny(context.TODO(), httpClient, url, false)
		if err != nil {
			panic(err)
		}
	case path != "":
		b, err := os.ReadFile(path)
		if err != nil {
			panic(err)
		}
		if err := yaml.Unmarshal(b, &c); err != nil {
			panic(err)
		}
	default:
		panic("url 和 i 参数不能都为空")
	}

	if insecure {
		convert.ToInsecure(&c)
	}
	s, eps, err := convert.Clash2sing(c, model.SINGLATEST)
	if err != nil {
		fmt.Println(err) // 个别节点转换失败不影响其余节点
	}

	tpl, err := os.ReadFile(template)
	if errors.Is(err, os.ErrNotExist) {
		tpl = configByte
	} else if err != nil {
		panic(err)
	}
	extOut := make([]any, len(singNodes))
	for i, node := range singNodes {
		extOut[i] = node
	}
	out, err := convert.Patch(tpl, s, eps, include, exclude, extOut, singTags...)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(outPath, out, 0o644); err != nil {
		panic(err)
	}
}
