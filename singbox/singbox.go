package singbox

type SingBoxOut struct {
	Password   string        `json:"password,omitempty"`
	Server     string        `json:"server,omitempty"`
	ServerPort int           `json:"server_port,omitempty"`
	Tag        string        `json:"tag,omitempty"`
	TLS        singTLS       `json:"tls,omitempty"`
	Transport  singTransport `json:"transport,omitempty"`
	Type       string        `json:"type,omitempty"`
	Method     string        `json:"method,omitempty"`
	AlterID    int           `json:"alter_id,omitempty"`
	Security   string        `json:"security,omitempty"`
	UUID       string        `json:"uuid,omitempty"`
	Default    string        `json:"default,omitempty"`
	Outbounds  []string      `json:"outbounds,omitempty"`
	Interval   string        `json:"interval,omitempty"`
	Tolerance  int           `json:"tolerance,omitempty"`
	URL        string        `json:"url,omitempty"`
}

type singTLS struct {
	Enabled    bool     `json:"enabled,omitempty"`
	ServerName string   `json:"server_name,omitempty"`
	Alpn       []string `json:"alpn,omitempty"`
	Insecure   bool     `json:"insecure,omitempty"`
}

type singTransport struct {
	Headers             map[string]string `json:"headers,omitempty"`
	Path                string            `json:"path,omitempty"`
	Type                string            `json:"type,omitempty"`
	EarlyDataHeaderName string            `json:"early_data_header_name,omitempty"`
	MaxEarlyData        int               `json:"max_early_data,omitempty"`
	Host                []string          `json:"host,omitempty"`
	Method              string            `json:"method,omitempty"`
	ServiceName         string            `json:"service_name,omitempty"`
}
