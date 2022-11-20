# clash2singbox
用于将 clash 配置文件，以及订阅链接转换为 sing-box 格式的配置文件。

## 用法
`./clash2singbox -i config.yaml` 或者 `./clash2singbox -url <订阅链接>` 。

更多用法见 `./clash2singbox -h`

只会修改目标文件的 dns.rules 和 outbounds，第一次运行会按模板修改。

默认开启 clash api，可通过例如 `clash.razord.top` 切换节点和代理模式。

## 支持协议
- shadowsocks （不包含插件）
- vmess (仅 ws 和 grpc)
- trojan
