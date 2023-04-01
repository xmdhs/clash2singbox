package httputils

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

var c = http.Client{Timeout: 10 * time.Second}

func HttpGet(url string) ([]byte, error) {
	reqs, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("HttpGet: %w", err)
	}
	reqs.Header.Set("Accept", "*/*")
	reqs.Header.Set("User-Agent", "clash2singbox (Must Clash Format)")
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
	b, err := io.ReadAll(rep.Body)
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
