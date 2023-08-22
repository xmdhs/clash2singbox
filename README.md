# clash2singbox
用于将 clash 或者 Clash.Meta 配置文件，以及订阅链接转换为 sing-box 格式的配置文件。

## 用法
`./clash2singbox -i config.yaml` 或者 `./clash2singbox -url <订阅链接>` 。

多个订阅链接使用 | 分割

更多用法见 `./clash2singbox -h`

只会修改目标文件的 outbounds，第一次运行会按模板修改。

默认开启 clash api，可通过例如 `clash.razord.top` 切换节点和代理模式。

## 支持协议
- shadowsocks （仅包含 v2ray-plugin, obfs 和 shadow-tls 插件）
- shadowsocksR
- vmess
- vless (含 reality)
- trojan
- socks5
- http
- hysteria
- tuic5
## 网页版本
https://github.com/xmdhs/clash2sfa
