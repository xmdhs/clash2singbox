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

	"github.com/samber/lo"
	"github.com/xmdhs/clash2singbox/convert"
	"github.com/xmdhs/clash2singbox/httputils"
	"github.com/xmdhs/clash2singbox/model/clash"
	"gopkg.in/yaml.v3"
)

var (
	url      string
	path     string
	outPath  string
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
	flag.StringVar(&include, "include", "", "urltest 选择的节点")
	flag.StringVar(&exclude, "exclude", "", "urltest 排除的节点")
	flag.BoolVar(&insecure, "insecure", false, "所有节点不验证证书")
	flag.BoolVar(&ignore, "ignore", true, "忽略无法转换的节点")
	flag.Parse()
}

func main() {
	c := clash.Clash{}
	var singList []map[string]any
	var tags []string
	if url != "" {
		var err error
		c, singList, tags, err = httputils.GetAny(context.TODO(), &http.Client{Timeout: 10 * time.Second}, url, false)
		if err != nil {
			panic(err)
		}
	} else if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			panic(err)
		}
		err = yaml.Unmarshal(b, &c)
		if err != nil {
			panic(err)
		}
	} else {
		panic("url 和 i 参数不能都为空")
	}

	if insecure {
		convert.ToInsecure(&c)
	}

	s, err := convert.Clash2sing(c)
	if err != nil {
		fmt.Println(err)
	}
	outb, err := os.ReadFile(outPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			outb = configByte
		} else {
			panic(err)
		}
	}

	outb, err = convert.Patch(outb, s, include, exclude, lo.Map(singList, func(item map[string]any, index int) any {
		return item
	}), tags...)
	if err != nil {
		panic(err)
	}

	os.WriteFile(outPath, outb, 0644)
}
