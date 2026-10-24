package parse

import (
	"encoding/json"
	"fmt"

	"github.com/kyomufs/proxprobe/internal/model"
)

// singboxOutbound — один outbound конфига sing-box.
//
// Поля tagged/urltest/selector не разбираются: это группы, а не серверы.
// Узлом считается outbound, у которого есть server и server_port.
type singboxOutbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server"`
	ServerPort any    `json:"server_port"`

	UUID     string `json:"uuid"`
	Password string `json:"password"`
	Method   string `json:"method"`
	Flow     string `json:"flow"`
	AlterID  any    `json:"alter_id"`
	Security string `json:"security"`

	Transport struct {
		Type        string            `json:"type"`
		Path        string            `json:"path"`
		Host        string            `json:"host"`
		Headers     map[string]string `json:"headers"`
		ServiceName string            `json:"service_name"`
	} `json:"transport"`

	TLS struct {
		Enabled    bool     `json:"enabled"`
		ServerName string   `json:"server_name"`
		Insecure   bool     `json:"insecure"`
		ALPN       []string `json:"alpn"`
		Reality    struct {
			Enabled   bool   `json:"enabled"`
			PublicKey string `json:"public_key"`
			ShortID   string `json:"short_id"`
		} `json:"reality"`
		UTLS struct {
			Enabled     bool   `json:"enabled"`
			Fingerprint string `json:"fingerprint"`
		} `json:"utls"`
	} `json:"tls"`

	Obfs struct {
		Type     string `json:"type"`
		Password string `json:"password"`
	} `json:"obfs"`
}

// Singbox разбирает конфиг sing-box.
//
// Группы (selector, urltest) и служебные выходы (direct, block, dns)
// пропускаются: в outbounds[] они лежат вперемешку с серверами.
func Singbox(body []byte, source string) *Result {
	res := &Result{}

	var cfg struct {
		Outbounds []singboxOutbound `json:"outbounds"`
	}
	if err := json.Unmarshal(body, &cfg); err != nil {
		res.skip(string(body[:min(len(body), 200)]), fmt.Sprintf("singbox: %v", err))
		return res
	}

	groupTypes := map[string]bool{
		"selector": true, "urltest": true, "direct": true,
		"block": true, "dns": true,
	}

	for _, ob := range cfg.Outbounds {
		if groupTypes[ob.Type] {
			continue
		}
		if ob.Server == "" {
			// Без адреса это не сервер (например, outbound типа "wireguard"
			// с ключами в отдельном блоке — таких в наших источниках нет).
			res.skip(ob.Tag, fmt.Sprintf("singbox: outbound type %q has no server", ob.Type))
			continue
		}
		node, err := singboxOutboundToNode(ob)
		if err != nil {
			res.skip(ob.Tag, err.Error())
			continue
		}
		node.Source = []string{source}
		raw, _ := json.Marshal(ob)
		var rawMap map[string]any
		_ = json.Unmarshal(raw, &rawMap)
		node.Raw = map[string]any{"singbox": rawMap}
		node.Finalize()
		res.Nodes = append(res.Nodes, *node)
	}
	return res
}

func singboxOutboundToNode(ob singboxOutbound) (*model.Node, error) {
	port := anyToInt(ob.ServerPort)
	if port == 0 {
		return nil, fmt.Errorf("singbox: %q has no server_port", ob.Tag)
	}

	n := &model.Node{
		Name:        ob.Tag,
		Server:      ob.Server,
		Port:        port,
		Network:     ob.Transport.Type,
		Path:        ob.Transport.Path,
		Host:        ob.Transport.Host,
		ServiceName: ob.Transport.ServiceName,
		SNI:         ob.TLS.ServerName,
		ALPN:        ob.TLS.ALPN,
		Insecure:    ob.TLS.Insecure,
		Flow:        ob.Flow,
	}
	if n.Network == "" {
		n.Network = model.NetTCP
	}
	if h, ok := ob.Transport.Headers["Host"]; ok && n.Host == "" {
		n.Host = h
	}

	switch ob.Type {
	case "vless":
		n.Proto = model.ProtoVLESS
		n.UUID = ob.UUID
	case "vmess":
		n.Proto = model.ProtoVMess
		n.UUID = ob.UUID
		n.Method = ob.Security
	case "trojan":
		n.Proto = model.ProtoTrojan
		n.Password = ob.Password
	case "shadowsocks":
		n.Proto = model.ProtoSS
		n.Method = ob.Method
		n.Password = ob.Password
	case "socks":
		n.Proto = model.ProtoSocks5
		n.UUID = ob.UUID
		n.Password = ob.Password
	case "hysteria2":
		n.Proto = model.ProtoHysteria2
		n.Password = ob.Password
		n.Path = ob.Obfs.Password // obfs-пароль
		n.Host = ob.Obfs.Type
	case "tuic":
		n.Proto = model.ProtoTuic
		n.UUID = ob.UUID
		n.Password = ob.Password
	case "anytls":
		n.Proto = model.ProtoAnyTLS
		n.Password = ob.Password
	default:
		return nil, fmt.Errorf("singbox: unsupported outbound type %q", ob.Type)
	}

	switch {
	case ob.TLS.Reality.Enabled || ob.TLS.Reality.PublicKey != "":
		n.Security = model.SecReality
		n.PublicKey = ob.TLS.Reality.PublicKey
		n.ShortID = ob.TLS.Reality.ShortID
	case ob.TLS.Enabled:
		n.Security = model.SecTLS
	default:
		n.Security = model.SecNone
	}
	if ob.TLS.UTLS.Fingerprint != "" {
		n.Fingerprint = ob.TLS.UTLS.Fingerprint
	}
	return n, nil
}
