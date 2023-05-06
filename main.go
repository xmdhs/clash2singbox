package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"net/http"
	"os"
	"time"

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
	flag.Parse()
}

func main() {
	c := clash.Clash{}
	if url != "" {
		var err error
		c, err = httputils.GetClash(context.TODO(), &http.Client{Timeout: 10 * time.Second}, url)
		if err != nil {
			panic(err)
		}
	} else if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			panic(err)
		}
		err = yaml.Unmarshal(b, c)
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

	outb, err = convert.Patch(outb, s, include, exclude, nil)
	if err != nil {
		panic(err)
	}

	os.WriteFile(outPath, outb, 0777)
}
