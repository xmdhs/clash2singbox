package clash

import (
	"gopkg.in/yaml.v3"
)

type Clash struct {
	Proxies []Proxies `yaml:"proxies"`
}

type Proxies struct {
	Name                 string            `yaml:"name"`
	Type                 string            `yaml:"type"`
	Server               string            `yaml:"server"`
	Port                 string            `yaml:"port"`
	Cipher               string            `yaml:"cipher"`
	Uuid                 string            `yaml:"uuid"`
	AlterId              int               `yaml:"alterId"`
	Udp                  bool              `yaml:"udp"`
	Tls                  bool              `yaml:"tls"`
	SkipCertVerify       bool              `yaml:"skip-cert-verify"`
	Servername           string            `yaml:"servername"`
	Network              string            `yaml:"network"`
	WsOpts               wsOpts            `yaml:"ws-opts"`
	WsHeaders            map[string]string `yaml:"ws-headers"`
	H2Opts               h2Opts            `yaml:"h2-opts"`
	HTTPOpts             hTTPOpts          `yaml:"http-opts"`
	GrpcOpts             grpcOpts          `yaml:"grpc-opts"`
	Username             string            `yaml:"username"`
	Password             string            `yaml:"password"`
	Sni                  string            `yaml:"sni"`
	Alpn                 []string          `yaml:"alpn"`
	Plugin               string            `yaml:"plugin"`
	PluginOpts           yaml.Node         `yaml:"plugin-opts"`
	Fingerprint          string            `yaml:"fingerprint"`
	Obfs                 string            `yaml:"obfs"`
	Protocol             string            `yaml:"protocol"`
	ObfsParam            string            `yaml:"obfs-param"`
	ProtocolParam        string            `yaml:"protocol-param"`
	ClientFingerprint    string            `yaml:"client-fingerprint"`
	Flow                 string            `yaml:"flow"`
	PacketEncoding       string            `yaml:"packet_encoding"`
	RealityOpts          realityOpts       `yaml:"reality-opts"`
	AuthStr              string            `yaml:"auth-str"`
	AuthStr1             string            `yaml:"auth_str"`
	CaStr                string            `yaml:"ca-str"`
	CaStr1               string            `yaml:"ca_str"`
	DisableMtuDiscovery  any               `yaml:"disable_mtu_discovery"`
	Down                 string            `yaml:"down"`
	FastOpen             bool              `yaml:"fast-open"`
	RecvWindow           int               `yaml:"recv-window"`
	RecvWindowConn       int               `yaml:"recv-window-conn"`
	RecvWindow1          int               `yaml:"recv_window"`
	RecvWindowConn1      int               `yaml:"recv_window_conn"`
	Up                   string            `yaml:"up"`
	Ports                string            `yaml:"ports"`
	Smux                 smuxOpts          `yaml:"smux"`
	UdpOverTcp           bool              `yaml:"udp-over-tcp"`
	IP                   string            `yaml:"ip"`
	IPv6                 string            `yaml:"ipv6"`
	PublicKey            string            `yaml:"public-key"`
	PreSharedKey         string            `yaml:"pre-shared-key"`
	PrivateKey           string            `yaml:"private-key"`
	Reserved             *wgReserved       `yaml:"reserved"`
	DialerProxy          string            `yaml:"dialer-proxy"`
	Peers                []wgPeer
	MTU                  int    `yaml:"mtu"`
	DisableSni           bool   `yaml:"disable-sni"`
	CongestionController string `yaml:"congestion-controller"`
	UdpRelayMode         string `yaml:"udp-relay-mode"`
	ReduceRtt            bool   `yaml:"reduce-rtt"`
	HeartbeatInterval    int    `yaml:"heartbeat-interval"`
	ObfsPassword         string `yaml:"obfs-password"`
}

type smuxOpts struct {
	Enabled        bool   `yaml:"enabled"`
	MaxConnections int    `yaml:"max-connections"`
	MaxStreams     int    `yaml:"max-streams"`
	MinStreams     int    `yaml:"min-streams"`
	Padding        bool   `yaml:"padding"`
	Protocol       string `yaml:"protocol"`
}

type grpcOpts struct {
	GrpcServiceName string `yaml:"grpc-service-name"`
}

type hTTPOpts struct {
	Headers map[string][]string `yaml:"headers"`
	Method  string              `yaml:"method"`
	Path    []string            `yaml:"path"`
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
	V2rayHttpUpgrade    bool              `yaml:"v2ray-http-upgrade"`
}

type realityOpts struct {
	PublicKey string `yaml:"public-key"`
	ShortId   string `yaml:"short-id"`
}
