package clash

type Clash struct {
	Proxies []Proxies `yaml:"proxies"`
}

type Proxies struct {
	Name           string   `yaml:"name"`
	Type           string   `yaml:"type"`
	Server         string   `yaml:"server"`
	Port           int      `yaml:"port"`
	Cipher         string   `yaml:"cipher"`
	Uuid           string   `yaml:"uuid"`
	AlterId        int      `yaml:"alterId"`
	Udp            bool     `yaml:"udp"`
	Tls            bool     `yaml:"tls"`
	SkipCertVerify bool     `yaml:"skip-cert-verify"`
	Servername     string   `yaml:"servername"`
	Network        string   `yaml:"network"`
	WsOpts         wsOpts   `yaml:"ws-opts"`
	H2Opts         h2Opts   `yaml:"h2-opts"`
	HTTPOpts       hTTPOpts `yaml:"http-opts"`
	GrpcOpts       grpcOpts `yaml:"grpc-opts"`
	Username       string   `yaml:"username"`
	Password       string   `yaml:"password"`
	Sni            string   `yaml:"sni"`
	Alpn           []string `yaml:"alpn"`
}

type grpcOpts struct {
	GrpcServiceName string `yaml:"grpc-service-name"`
}

type hTTPOpts struct {
	Headers map[string]string `yaml:"headers"`
	Method  string            `yaml:"method"`
	Path    []string          `yaml:"path"`
}

type h2Opts struct {
	Host []string `yaml:"host"`
	Path string   `yaml:"path"`
}

type wsOpts struct {
	EarlyDataHeaderName string            `yaml:"early-data-header-name"`
	Headers             map[string]string `yaml:"headers"`
	MaxEarlyData        int               `yaml:"max-early-data"`
	Path                string            `yaml:"path"`
}
