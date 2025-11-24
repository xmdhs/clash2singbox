package convert

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/xmdhs/clash2singbox/model/clash"
)

func ParseURL(s string) (clash.Proxies, error) {
	s = strings.TrimSpace(s)
	u, err := url.Parse(s)
	if err != nil {
		return clash.Proxies{}, err
	}
	var p clash.Proxies
	switch u.Scheme {
	case "ss":
		p, err = parseSs(u)
	case "vmess":
		p, err = parseVmess(s)
	case "vless":
		p, err = parseVless(u)
	case "trojan":
		p, err = parseTrojan(u)
	case "hysteria":
		p, err = parseHysteria(u)
	case "hy2", "hysteria2":
		p, err = parseHysteria2(u)
	case "tuic":
		p, err = parseTuic(u)
	case "socks5":
		p, err = parseSocks5(u)
	case "http", "https":
		p, err = parseHttp(u)
	case "anytls":
		p, err = parseAnytls(u)
	default:
		return clash.Proxies{}, fmt.Errorf("unsupported protocol: %s", u.Scheme)
	}
	if err != nil {
		return clash.Proxies{}, fmt.Errorf("%s: %w", s, err)
	}
	return p, nil
}

func parseHttp(u *url.URL) (clash.Proxies, error) {
	p := clash.Proxies{
		Name:   u.Fragment,
		Type:   "http",
		Server: u.Hostname(),
		Port:   u.Port(),
	}
	if u.User != nil {
		p.Username = u.User.Username()
		pass, ok := u.User.Password()
		if ok {
			p.Password = pass
		}
	}
	if u.Scheme == "https" {
		p.Tls = clash.MyBool(true)
	}
	return p, nil
}

func parseSocks5(u *url.URL) (clash.Proxies, error) {
	p := clash.Proxies{
		Name:   u.Fragment,
		Type:   "socks5",
		Server: u.Hostname(),
		Port:   u.Port(),
	}
	if u.User != nil {
		p.Username = u.User.Username()
		pass, ok := u.User.Password()
		if ok {
			p.Password = pass
		}
	}
	return p, nil
}

func parseTuic(u *url.URL) (clash.Proxies, error) {
	p := clash.Proxies{
		Name:     u.Fragment,
		Type:     "tuic",
		Server:   u.Hostname(),
		Port:     u.Port(),
		Password: u.User.Username(),
	}
	q := u.Query()
	if sni, ok := q["sni"]; ok {
		p.Sni = sni[0]
	}
	if alpn, ok := q["alpn"]; ok {
		p.Alpn = strings.Split(alpn[0], ",")
	}
	if scv, ok := q["skip-cert-verify"]; ok && len(scv) > 0 && (scv[0] == "true" || scv[0] == "1") {
		p.SkipCertVerify = clash.MyBool(true)
	}
	if ds, ok := q["disable-sni"]; ok && len(ds) > 0 && (ds[0] == "true" || ds[0] == "1") {
		p.DisableSni = clash.MyBool(true)
	}
	if cr, ok := q["congestion-controller"]; ok {
		p.CongestionController = cr[0]
	}
	if um, ok := q["udp-relay-mode"]; ok {
		p.UdpRelayMode = um[0]
	}
	if rr, ok := q["reduce-rtt"]; ok && len(rr) > 0 && (rr[0] == "true" || rr[0] == "1") {
		p.ReduceRtt = clash.MyBool(true)
	}
	if hi, ok := q["heartbeat-interval"]; ok {
		i, err := strconv.Atoi(hi[0])
		if err == nil {
			p.HeartbeatInterval = clash.MyInt(i)
		}
	}
	return p, nil
}

func parseHysteria2(u *url.URL) (clash.Proxies, error) {
	p := clash.Proxies{
		Name:     u.Fragment,
		Type:     "hysteria2",
		Server:   u.Hostname(),
		Port:     u.Port(),
		Password: u.User.Username(),
	}
	q := u.Query()
	if scv, ok := q["insecure"]; ok && len(scv) > 0 && scv[0] == "1" {
		p.SkipCertVerify = clash.MyBool(true)
	}
	if sni, ok := q["sni"]; ok {
		p.Sni = sni[0]
	}
	if obfs, ok := q["obfs"]; ok {
		p.Obfs = obfs[0]
	}
	if op, ok := q["obfs-password"]; ok {
		p.ObfsPassword = op[0]
	}
	if mport, ok := q["mport"]; ok {
		p.Ports = mport[0]
	}
	return p, nil
}

func parseHysteria(u *url.URL) (clash.Proxies, error) {
	p := clash.Proxies{
		Name:   u.Fragment,
		Type:   "hysteria",
		Server: u.Hostname(),
		Port:   u.Port(),
	}
	q := u.Query()
	if alpn, ok := q["alpn"]; ok {
		p.Alpn = strings.Split(alpn[0], ",")
	}
	if scv, ok := q["insecure"]; ok && len(scv) > 0 && (scv[0] == "1" || scv[0] == "true") {
		p.SkipCertVerify = clash.MyBool(true)
	}
	if auth, ok := q["auth"]; ok {
		p.AuthStr = auth[0]
	}
	if ports, ok := q["mport"]; ok {
		p.Ports = ports[0]
	}
	if op, ok := q["obfsParam"]; ok {
		p.Obfs = op[0]
	}
	if up, ok := q["upmbps"]; ok {
		p.Up = up[0]
	}
	if down, ok := q["downmbps"]; ok {
		p.Down = down[0]
	}
	if obfs, ok := q["obfs"]; ok {
		p.Obfs = obfs[0]
	}
	if fo, ok := q["fast-open"]; ok && len(fo) > 0 && (fo[0] == "1" || fo[0] == "true") {
		p.FastOpen = clash.MyBool(true)
	}
	if rwc, ok := q["recv-window-conn"]; ok {
		i, err := strconv.Atoi(rwc[0])
		if err == nil {
			p.RecvWindowConn = clash.MyInt(i)
		}
	}
	if rw, ok := q["recv-window"]; ok {
		i, err := strconv.Atoi(rw[0])
		if err == nil {
			p.RecvWindow = clash.MyInt(i)
		}
	}
	if dmd, ok := q["disable-mtu-discovery"]; ok && len(dmd) > 0 && (dmd[0] == "1" || dmd[0] == "true") {
		p.DisableMtuDiscovery = clash.MyBool(true)
	}
	if fp, ok := q["fingerprint"]; ok {
		p.Fingerprint = fp[0]
	}
	if protocol, ok := q["protocol"]; ok {
		p.Protocol = protocol[0]
	}
	if sni, ok := q["sni"]; ok {
		p.Sni = sni[0]
	}

	return p, nil
}

func parseTrojan(u *url.URL) (clash.Proxies, error) {
	p := clash.Proxies{
		Type:   "trojan",
		Name:   u.Fragment,
		Server: u.Hostname(),
		Port:   u.Port(),
	}
	if u.User != nil {
		p.Password = u.User.Username()
	}

	q := u.Query()
	if t, ok := q["type"]; ok {
		p.Network = t[0]
	}
	if host, ok := q["host"]; ok {
		p.WsOpts.Headers = map[string]string{
			"Host": host[0],
		}
	}
	if path, ok := q["path"]; ok {
		p.WsOpts.Path = path[0]
	}
	if alpn, ok := q["alpn"]; ok {
		p.Alpn = strings.Split(alpn[0], ",")
	}
	if sni, ok := q["sni"]; ok {
		p.Sni = sni[0]
	}
	if scv, ok := q["skip-cert-verify"]; ok && len(scv) > 0 && (scv[0] == "1" || scv[0] == "true") {
		p.SkipCertVerify = clash.MyBool(true)
	}
	if fp, ok := q["fingerprint"]; ok {
		p.Fingerprint = fp[0]
	}
	if fp, ok := q["fp"]; ok {
		p.Fingerprint = fp[0]
	}
	if cfp, ok := q["client-fingerprint"]; ok {
		p.ClientFingerprint = cfp[0]
	}
	if allowInsecure, ok := q["allowInsecure"]; ok && len(allowInsecure) > 0 && (allowInsecure[0] == "1" || allowInsecure[0] == "true") {
		p.SkipCertVerify = clash.MyBool(true)
	}
	return p, nil
}

func parseVless(u *url.URL) (clash.Proxies, error) {
	p := clash.Proxies{
		Type:   "vless",
		Name:   u.Fragment,
		Server: u.Hostname(),
		Port:   u.Port(),
		Uuid:   u.User.String(),
	}
	q := u.Query()
	if security, ok := q["security"]; ok && len(security) > 0 && security[0] != "none" {
		p.Tls = clash.MyBool(true)
		if security[0] == "reality" {
			p.RealityOpts.PublicKey = q.Get("pbk")
			p.RealityOpts.ShortId = q.Get("sid")
		}
	}

	p.Servername = q.Get("sni")
	if p.Servername == "" {
		p.Servername = q.Get("peer")
	}
	p.Flow = q.Get("flow")
	p.ClientFingerprint = q.Get("fp")
	if alpn, ok := q["alpn"]; ok {
		p.Alpn = strings.Split(alpn[0], ",")
	}
	if scv, ok := q["allowinsecure"]; ok && len(scv) > 0 && (scv[0] == "1" || strings.ToLower(scv[0]) == "true") {
		p.SkipCertVerify = clash.MyBool(true)
	}
	p.Network = q.Get("type")

	switch p.Network {
	case "ws", "http", "grpc", "h2":
		host := q.Get("host")
		if host == "" {
			host = q.Get("obfsparam")
		}
		path := q.Get("path")
		switch p.Network {
		case "ws":
			p.WsOpts.Path = path
			if host != "" {
				p.WsOpts.Headers = map[string]string{
					"Host": host,
				}
			}
			if q.Get("headerType") == "http" {
				p.WsOpts.V2rayHttpUpgrade = clash.MyBool(true)
			}
		case "http":
			p.HTTPOpts.Path = []string{path}
			if host != "" {
				p.HTTPOpts.Headers = map[string][]string{
					"Host": {host},
				}
			}
		case "h2":
			p.H2Opts.Path = path
			if host != "" {
				p.H2Opts.Host = []string{host}
			}
		case "grpc":
			p.GrpcOpts.GrpcServiceName = path
		}
	}
	if p.Tls && p.Servername == "" {
		if host, ok := p.WsOpts.Headers["Host"]; ok {
			p.Servername = host
		} else if len(p.HTTPOpts.Headers["Host"]) > 0 {
			p.Servername = p.HTTPOpts.Headers["Host"][0]
		}
	}

	return p, nil
}

func parseVmess(s string) (clash.Proxies, error) {
	s = strings.TrimPrefix(s, "vmess://")
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return clash.Proxies{}, err
	}
	v := struct {
		Ps   string `json:"ps"`
		Add  string `json:"add"`
		Port any    `json:"port"`
		Id   string `json:"id"`
		Aid  any    `json:"aid"`
		Scy  string `json:"scy"`
		Net  string `json:"net"`
		Type string `json:"type"`
		Host string `json:"host"`
		Path string `json:"path"`
		Tls  string `json:"tls"`
		Sni  string `json:"sni"`
		Alpn string `json:"alpn"`
		Fp   string `json:"fp"`
	}{}
	err = json.Unmarshal(b, &v)
	if err != nil {
		return clash.Proxies{}, err
	}
	name := v.Ps
	p := clash.Proxies{
		Type:   "vmess",
		Name:   name,
		Server: v.Add,
		Uuid:   v.Id,
		Cipher: v.Scy,
	}

	switch port := v.Port.(type) {
	case string:
		p.Port = port
	case float64:
		p.Port = strconv.FormatFloat(port, 'f', -1, 64)
	}

	switch aid := v.Aid.(type) {
	case string:
		i, err := strconv.Atoi(aid)
		if err == nil {
			p.AlterId = clash.MyInt(i)
		}
	case float64:
		p.AlterId = clash.MyInt(int(aid))
	}

	if v.Tls == "tls" {
		p.Tls = clash.MyBool(true)
		p.Servername = v.Sni
	}

	p.Network = v.Net
	switch p.Network {
	case "ws":
		p.WsOpts.Path = v.Path
		p.WsOpts.Headers = map[string]string{
			"Host": v.Host,
		}
	case "http":
		p.HTTPOpts.Path = []string{v.Path}
		p.HTTPOpts.Headers = map[string][]string{
			"Host": {v.Host},
		}
	case "h2":
		p.H2Opts.Path = v.Path
		p.H2Opts.Host = []string{v.Host}
	case "grpc":
		p.GrpcOpts.GrpcServiceName = v.Path

	}
	if v.Alpn != "" {
		p.Alpn = strings.Split(v.Alpn, ",")
	}
	p.ClientFingerprint = v.Fp
	return p, nil
}

func parseSs(u *url.URL) (clash.Proxies, error) {
	p := clash.Proxies{
		Type:   "ss",
		Server: u.Hostname(),
		Port:   u.Port(),
		Name:   u.Fragment,
	}
	password, ok := u.User.Password()
	decodedUserInfo, err := base64.RawURLEncoding.DecodeString(u.User.Username())
	if err == nil && !ok {
		parts := strings.SplitN(string(decodedUserInfo), ":", 2)
		if len(parts) == 2 {
			p.Cipher = parts[0]
			p.Password = parts[1]
		}
	} else {
		if ok {
			p.Password = password
			p.Cipher = u.User.Username()
		} else {
			return clash.Proxies{}, fmt.Errorf("invalid ss link")
		}
	}

	q := u.Query()

	if plugin, ok := q["plugin"]; ok {
		if len(plugin) > 0 {
			pluginStr, err := url.QueryUnescape(plugin[0])
			if err != nil {
				return clash.Proxies{}, err
			}
			parts := strings.Split(pluginStr, ";")
			if len(parts) < 2 {
				return clash.Proxies{}, err
			}
			opts := make(map[string]string)
			for _, part := range parts[1:] {
				kv := strings.SplitN(part, "=", 2)
				if len(kv) == 2 {
					opts[kv[0]] = kv[1]
				}
			}

			switch parts[0] {
			case "obfs-local", "simple-obfs":
				p.Plugin = "obfs"
				pluginOpts := make(map[string]string)
				pluginOpts["mode"] = opts["obfs"]
				if host, ok := opts["obfs-host"]; ok {
					pluginOpts["host"] = host
				}
				err = p.PluginOpts.Encode(pluginOpts)
				if err != nil {
					return clash.Proxies{}, err
				}
			case "v2ray-plugin":
				p.Plugin = "v2ray-plugin"
				pluginOpts := make(map[string]any)
				pluginOpts["mode"] = opts["mode"]
				if _, ok := opts["tls"]; ok {
					pluginOpts["tls"] = true
				}
				pluginOpts["host"] = opts["host"]
				err = p.PluginOpts.Encode(pluginOpts)
				if err != nil {
					return clash.Proxies{}, err
				}

			}
		}
	}

	if tfo, ok := q["tfo"]; ok && len(tfo) > 0 && (tfo[0] == "1" || tfo[0] == "true") {
		p.Tfo = true
	}
	return p, nil
}

func parseAnytls(u *url.URL) (clash.Proxies, error) {
	p := clash.Proxies{
		Name:   u.Fragment,
		Type:   "anytls",
		Server: u.Hostname(),
		Port:   u.Port(),
	}
	p.Password = u.User.Username()
	q := u.Query()

	p.Servername = q.Get("sni")
	if v := q.Get("insecure"); v == "1" {
		p.SkipCertVerify = true
	}
	return p, nil
}
