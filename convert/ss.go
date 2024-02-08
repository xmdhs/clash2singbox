package convert

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/xmdhs/clash2singbox/model/clash"
	"github.com/xmdhs/clash2singbox/model/singbox"
	"gopkg.in/yaml.v3"
)

func ss(p *clash.Proxies, s *singbox.SingBoxOut) ([]singbox.SingBoxOut, error) {
	s.Method = p.Cipher
	if !p.Udp {
		s.Network = "tcp"
	}
	if p.Obfs != "" {
		s.Obfs = &singbox.SingObfs{
			Value: p.Obfs,
		}
	}
	s.ProtocolParam = p.ProtocolParam
	s.Protocol = p.Protocol
	s.ObfsParam = p.ObfsParam

	if p.UdpOverTcp {
		s.UdpOverTcp = &singbox.SingUdpOverTcp{Enabled: true}
	}

	if p.Plugin != "" {
		if p.Plugin == "shadow-tls" {
			sl, err := shadowTls(p, s)
			if err != nil {
				return nil, fmt.Errorf("ss: %w", err)
			}
			return sl, nil
		}
		err := ssPlugin(p.PluginOpts, s, p.Plugin)
		if err != nil {
			return nil, fmt.Errorf("ss: %w", err)
		}
	}
	return []singbox.SingBoxOut{*s}, nil
}

type obfs struct {
	Mode string `yaml:"mode"`
	Host string `yaml:"host"`
}

func (o obfs) String() string {
	sl := []string{}
	if o.Mode != "" {
		sl = append(sl, "obfs="+backslashEscape(o.Mode))
	}
	if o.Host != "" {
		sl = append(sl, "obfs-host="+backslashEscape(o.Host))
	}
	return strings.Join(sl, ";")
}

type shadowTlsPlugin struct {
	Host     string `yaml:"host"`
	Password string `yaml:"password"`
	Version  int    `yaml:"version"`
}

func shadowTls(p *clash.Proxies, s *singbox.SingBoxOut) ([]singbox.SingBoxOut, error) {
	v := shadowTlsPlugin{}
	err := p.PluginOpts.Decode(&v)
	if err != nil {
		return nil, fmt.Errorf("shadowTls: %w", err)
	}
	ss := *s
	ss.Server = ""
	ss.ServerPort = 0
	ss.Detour = s.Tag + "-shadowtls"

	tlss := singbox.SingBoxOut{}
	tlss.Ignored = true
	tlss.Type = "shadowtls"
	tlss.Tag = ss.Detour
	tlss.Server = s.Server
	tlss.ServerPort = s.ServerPort
	tlss.Version = v.Version
	tlss.Password = v.Password
	tlss.TLS = &singbox.SingTLS{
		Enabled:    true,
		ServerName: v.Host,
	}
	if p.ClientFingerprint != "" {
		tlss.TLS.Utls = &singbox.SingUtls{
			Enabled:     true,
			Fingerprint: p.ClientFingerprint,
		}
	}
	return []singbox.SingBoxOut{ss, tlss}, nil
}

type v2rayPlugin struct {
	Mode string `yaml:"mode"`
	Tls  bool   `yaml:"tls"`
	Host string `yaml:"host"`
	Path string `yaml:"path"`
	Mux  bool   `yaml:"mux"`
}

func (v v2rayPlugin) String() string {
	sl := []string{}
	if v.Tls {
		sl = append(sl, "tls")
	}
	if v.Host != "" {
		sl = append(sl, "host="+backslashEscape(v.Host))
	}
	if v.Path != "" {
		sl = append(sl, "path="+backslashEscape(v.Path))
	}
	if v.Mode != "" {
		sl = append(sl, "mode="+backslashEscape(v.Mode))
	}
	if v.Mux {
		sl = append(sl, "mux")
	}
	return strings.Join(sl, ";")
}

var ErrNotSupportPlugin = errors.New("不支持的插件")

func ssPlugin(p yaml.Node, s *singbox.SingBoxOut, plugin string) error {
	switch plugin {
	case "v2ray-plugin":
		s.Plugin = "v2ray-plugin"
		v := v2rayPlugin{}
		err := p.Decode(&v)
		if err != nil {
			return fmt.Errorf("ssPlugin: %w", err)
		}
		s.PluginOpts = v.String()
		return nil
	case "obfs":
		s.Plugin = "obfs-local"
		o := obfs{}
		err := p.Decode(&o)
		if err != nil {
			return fmt.Errorf("ssPlugin: %w", err)
		}
		s.PluginOpts = o.String()
		return nil
	}
	return fmt.Errorf("ssPlugin: %w", ErrNotSupportPlugin)
}

// Escape backslashes and all the bytes that are in set.
// https://github.com/shadowsocks/v2ray-plugin/blob/master/args.go#L157
func backslashEscape(s string) string {
	var buf bytes.Buffer
	set := []byte{'=', ';'}
	for _, b := range []byte(s) {
		if b == '\\' || bytes.IndexByte(set, b) != -1 {
			buf.WriteByte('\\')
		}
		buf.WriteByte(b)
	}
	return buf.String()
}
