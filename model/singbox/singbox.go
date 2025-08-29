package singbox

import "encoding/json"

// FilterRule 定义过滤规则
type FilterRule struct {
	Action   string `json:"action"`   // "include" 或 "exclude"
	Keywords string `json:"keywords"` // 关键词，支持正则表达式，用|分隔
}

type SingBoxOut struct {
	Username                 string                    `json:"username,omitempty"`
	Password                 string                    `json:"password,omitempty"`
	Server                   string                    `json:"server,omitempty"`
	ServerPort               int                       `json:"server_port,omitempty"`
	ServerPorts              []string                  `json:"server_ports,omitempty"`
	Tag                      string                    `json:"tag,omitempty"`
	TLS                      *SingTLS                  `json:"tls,omitempty"`
	Transport                *SingTransport            `json:"transport,omitempty"`
	Type                     string                    `json:"type,omitempty"`
	Method                   string                    `json:"method,omitempty"`
	AlterID                  int                       `json:"alter_id,omitempty"`
	Security                 string                    `json:"security,omitempty"`
	UUID                     string                    `json:"uuid,omitempty"`
	Default                  string                    `json:"default,omitempty"`
	Outbounds                []string                  `json:"outbounds,omitempty"`
	Interval                 string                    `json:"interval,omitempty"`
	Tolerance                int                       `json:"tolerance,omitempty"`
	URL                      string                    `json:"url,omitempty"`
	Network                  interface{}               `json:"network,omitempty"`
	Plugin                   string                    `json:"plugin,omitempty"`
	PluginOpts               string                    `json:"plugin_opts,omitempty"`
	ObfsParam                string                    `json:"obfs_param,omitempty"`
	Protocol                 string                    `json:"protocol,omitempty"`
	ProtocolParam            string                    `json:"protocol_param,omitempty"`
	Flow                     string                    `json:"flow,omitempty"`
	PacketEncoding           string                    `json:"packet_encoding,omitempty"`
	AuthStr                  string                    `json:"auth_str,omitempty"`
	DisableMtuDiscovery      bool                      `json:"disable_mtu_discovery,omitempty"`
	Down                     string                    `json:"down,omitempty"`
	DownMbps                 int                       `json:"down_mbps,omitempty"`
	RecvWindow               int                       `json:"recv_window,omitempty"`
	RecvWindowConn           int                       `json:"recv_window_conn,omitempty"`
	Up                       string                    `json:"up,omitempty"`
	UpMbps                   int                       `json:"up_mbps,omitempty"`
	Detour                   string                    `json:"detour,omitempty"`
	Multiplex                *SingMultiplex            `json:"multiplex,omitempty"`
	Version                  int                       `json:"version,omitempty"`
	UdpOverTcp               *SingUdpOverTcp           `json:"udp_over_tcp,omitempty"`
	SystemInterface          bool                      `json:"system_interface,omitempty"`
	InterfaceName            string                    `json:"interface_name,omitempty"`
	LocalAddress             []string                  `json:"local_address,omitempty"`
	PrivateKey               string                    `json:"private_key,omitempty"`
	Peers                    []*SingWireguardMultiPeer `json:"peers,omitempty"`
	PeerPublicKey            string                    `json:"peer_public_key,omitempty"`
	PreSharedKey             string                    `json:"pre_shared_key,omitempty"`
	Reserved                 []int64                   `json:"reserved,omitempty"`
	MTU                      uint                      `json:"mtu,omitempty"`
	CongestionController     string                    `json:"congestion_control,omitempty"`
	UdpRelayMode             string                    `json:"udp_relay_mode,omitempty"`
	ZeroRttHandshake         bool                      `json:"zero_rtt_handshake,omitempty"`
	Heartbeat                string                    `json:"heartbeat,omitempty"`
	Obfs                     *SingObfs                 `json:"obfs,omitempty"`
	Ignored                  bool                      `json:"-"`
	TcpFastOpen              bool                      `json:"tcp_fast_open,omitempty"`
	TcpMultiPath             bool                      `json:"tcp_multi_path,omitempty"`
	Visible                  []string                  `json:"-"`
	IdleSessionCheckInterval string                    `json:"idle_session_check_interval,omitempty"`
	IdleSessionTimeout       string                    `json:"idle_session_timeout,omitempty"`
	MinIdleSession           int                       `json:"min_idle_session,omitempty"`
	Filter                   []FilterRule              `json:"filter,omitempty"`
}

type SingUdpOverTcp struct {
	Enabled bool `json:"enabled,omitempty"`
}

type SingTLS struct {
	Enabled     bool         `json:"enabled,omitempty"`
	ServerName  string       `json:"server_name,omitempty"`
	Alpn        []string     `json:"alpn,omitempty"`
	Insecure    bool         `json:"insecure,omitempty"`
	Utls        *SingUtls    `json:"utls,omitempty"`
	Reality     *SingReality `json:"reality,omitempty"`
	Certificate string       `json:"certificate,omitempty"`
}

type SingUtls struct {
	Enabled     bool   `json:"enabled,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type SingReality struct {
	Enabled   bool   `json:"enabled,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	ShortID   string `json:"short_id,omitempty"`
}

type SingTransport struct {
	Headers             map[string][]string `json:"headers,omitempty"`
	Path                string              `json:"path,omitempty"`
	Type                string              `json:"type,omitempty"`
	EarlyDataHeaderName string              `json:"early_data_header_name,omitempty"`
	MaxEarlyData        int                 `json:"max_early_data,omitempty"`
	Host                any                 `json:"host,omitempty"`
	Method              string              `json:"method,omitempty"`
	ServiceName         string              `json:"service_name,omitempty"`
}

type SingMultiplex struct {
	Enabled        bool   `json:"enabled,omitempty"`
	MaxConnections int    `json:"max_connections,omitempty"`
	MinStreams     int    `json:"min_streams,omitempty"`
	MaxStreams     int    `json:"max_streams,omitempty"`
	Padding        bool   `json:"padding,omitempty"`
	Protocol       string `json:"protocol,omitempty"`
}

type SingWireguardMultiPeer struct {
	Server       string   `json:"server,omitempty"`
	ServerPort   int      `json:"server_port,omitempty"`
	PublicKey    string   `json:"public_key,omitempty"`
	PreSharedKey string   `json:"pre_shared_key,omitempty"`
	AllowedIps   []string `json:"allowed_ips,omitempty"`
	Reserved     []int64  `json:"reserved,omitempty"`
}

type SingObfs struct {
	Value string
	Type  string
}

type singObfsHysteria2 struct {
	Password string `json:"password"`
	Type     string `json:"type"`
}

func (s SingObfs) MarshalJSON() ([]byte, error) {
	if s.Type == "" {
		return json.Marshal(s.Value)
	}
	ns := singObfsHysteria2{
		Password: s.Value,
		Type:     s.Type,
	}
	return json.Marshal(ns)
}
