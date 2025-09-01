package httputils

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

func HttpGet(cxt context.Context, c *http.Client, url string, maxByte int64) ([]byte, error) {
	reqs, err := http.NewRequestWithContext(cxt, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("HttpGet: %w", err)
	}
	reqs.Header.Set("Accept", "*/*")
	reqs.Header.Set("User-Agent", "clash2singbox (sing-box 1.12.0 SFA Clash ClashMeta clash.meta)")
	rep, err := c.Do(reqs)
	if rep != nil {
		defer rep.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("HttpGet: %w", err)
	}
	if rep.StatusCode != http.StatusOK {
		return nil, Errpget{Msg: rep.Status, url: url}
	}
	b, err := io.ReadAll(io.LimitReader(rep.Body, maxByte))
	if err != nil {
		return nil, fmt.Errorf("HttpGet: %w", err)
	}
	return b, nil
}

type Errpget struct {
	Msg string
	url string
}

func (h Errpget) Error() string {
	return "not 200: " + h.Msg + " " + h.url
}
