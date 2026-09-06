package httputils

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// userAgent 伪装成 sing-box 客户端，部分机场会按 UA 决定返回的订阅格式。
const userAgent = "sing-box 1.14.0 (ClashMetaForAndroid) clash2singbox"

// HttpGet 抓取 url 并最多读取 maxByte 字节；非 200 响应返回 Errpget。
func HttpGet(ctx context.Context, c *http.Client, url string, maxByte int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("HttpGet: %w", err)
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HttpGet: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, Errpget{Msg: resp.Status, url: url}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxByte))
	if err != nil {
		return nil, fmt.Errorf("HttpGet: %w", err)
	}
	return b, nil
}

// Errpget 表示订阅服务器返回了非 200 状态。
type Errpget struct {
	Msg string
	url string
}

func (h Errpget) Error() string {
	return "not 200: " + h.Msg + " " + h.url
}
