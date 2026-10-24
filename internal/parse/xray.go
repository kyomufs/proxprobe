package parse

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/kyomufs/proxprobe/internal/model"
)

// xrayConfig — один конфиг Xray. Источник pro1link отдаёт их МАССИВОМ:
// каждый элемент — самостоятельный конфиг со своими dns, routing,
// inbounds и outbounds, а remarks — имя сервера.
type xrayConfig struct {
	Remarks   string         `json:"remarks"`
	Inbounds  []xrayInbound  `json:"inbounds"`
	Outbounds []xrayOutbound `json:"outbounds"`
	Routing   map[string]any `json:"routing"`
	DNS       map[string]any `json:"dns"`
}

type xrayInbound struct {
	Tag      string `json:"tag"`
	Port     any    `json:"port"`
	Protocol string `json:"protocol"`
}

type xrayOutbound struct {
	Tag            string         `json:"tag"`
	Protocol       string         `json:"protocol"`
	Settings       map[string]any `json:"settings"`
	StreamSettings struct {
		Network         string `json:"network"`
		Security        string `json:"security"`
		RealitySettings struct {
			ServerName  string `json:"serverName"`
			PublicKey   string `json:"publicKey"`
			ShortID     string `json:"shortId"`
			SpiderX     string `json:"spiderX"`
			Fingerprint string `json:"fingerprint"`
		} `json:"realitySettings"`
		TLSSettings struct {
			ServerName    string   `json:"serverName"`
			ALPN          []string `json:"alpn"`
			AllowInsecure bool     `json:"allowInsecure"`
		} `json:"tlsSettings"`
		WSSettings struct {
			Path    string            `json:"path"`
			Headers map[string]string `json:"headers"`
		} `json:"wsSettings"`
		GRPCSettings struct {
			ServiceName string `json:"serviceName"`
		} `json:"grpcSettings"`
		XHTTPSettings struct {
			Path string `json:"path"`
			Host string `json:"host"`
		} `json:"xhttpSettings"`
		// hysteriaSettings несёт пароль: в бандлах pro1link сам адрес лежит
		// плоско в settings, а auth — здесь.
		HysteriaSettings struct {
			Version any `json:"version"`
			Auth    any `json:"auth"`
		} `json:"hysteriaSettings"`
	} `json:"streamSettings"`
}

// служебные протоколы: это не серверы, а выходы в сеть, в дырку и в никуда.
var xrayServiceProtocols = map[string]bool{
	"freedom": true, "blackhole": true, "dns": true, "loopback": true,
}

// XrayBundles разбирает массив конфигов Xray.
//
// Из каждого бандла берутся только outbound'ы с реальным протоколом:
// freedom/blackhole/dns/loopback — это инфраструктура конфига, а не серверы.
// Если бандл содержит несколько таких outbound'ов (бывает у мульти-выходных
// конфигов), каждый становится отдельным узлом.
func XrayBundles(body []byte, source string) *Result {
	res := &Result{}

	var configs []xrayConfig
	if err := json.Unmarshal(body, &configs); err != nil {
		res.skip(string(body[:min(len(body), 200)]), fmt.Sprintf("xray: not a bundle array: %v", err))
		return res
	}
	if len(configs) == 0 {
		res.skip("", "xray: bundle array is empty")
		return res
	}

	for _, cfg := range configs {
		real := make([]xrayOutbound, 0, len(cfg.Outbounds))
		for _, ob := range cfg.Outbounds {
			if xrayServiceProtocols[ob.Protocol] {
				continue
			}
			real = append(real, ob)
		}
		if len(real) == 0 {
			res.skip(cfg.Remarks, "xray: bundle contains no server outbound")
			continue
		}
		for i, ob := range real {
			node, err := xrayOutboundToNode(ob, cfg.Remarks, len(real) > 1, i)
			if err != nil {
				res.skip(cfg.Remarks, err.Error())
				continue
			}
			node.Source = []string{source}
			node.Raw = map[string]any{"xray": outboundToMap(ob), "bundled_remarks": cfg.Remarks}
			node.Finalize()
			res.Nodes = append(res.Nodes, *node)
		}
	}
	return res
}

// XrayConfig разбирает одиночный конфиг Xray (объект, не массив).
func XrayConfig(body []byte, source string) *Result {
	res := &Result{}
	var cfg xrayConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		res.skip(string(body[:min(len(body), 200)]), fmt.Sprintf("xray: %v", err))
		return res
	}
	for _, ob := range cfg.Outbounds {
		if xrayServiceProtocols[ob.Protocol] {
			continue
		}
		node, err := xrayOutboundToNode(ob, cfg.Remarks, false, 0)
		if err != nil {
			res.skip(ob.Tag, err.Error())
			continue
		}
		node.Source = []string{source}
		node.Raw = map[string]any{"xray": outboundToMap(ob)}
		node.Finalize()
		res.Nodes = append(res.Nodes, *node)
	}
	return res
}

func outboundToMap(ob xrayOutbound) map[string]any {
	raw, _ := json.Marshal(ob)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m
}

func xrayOutboundToNode(ob xrayOutbound, remarks string, multi bool, index int) (*model.Node, error) {
	server, port, user, err := xrayEndpoint(ob)
	if err != nil {
		return nil, err
	}

	name := remarks
	if name == "" {
		name = ob.Tag
	}
	if multi {
		// У бандла с несколькими выходами одно имя на всех — различаем индексом,
		// иначе дедуп склеит разные серверы в один.
		name = fmt.Sprintf("%s (%d)", name, index+1)
	}

	ss := ob.StreamSettings
	n := &model.Node{
		Name:        name,
		Server:      server,
		Port:        port,
		Network:     ss.Network,
		Security:    ss.Security,
		SNI:         ss.RealitySettings.ServerName,
		PublicKey:   ss.RealitySettings.PublicKey,
		ShortID:     ss.RealitySettings.ShortID,
		SpiderX:     ss.RealitySettings.SpiderX,
		Fingerprint: ss.RealitySettings.Fingerprint,
		Path:        ss.WSSettings.Path,
		ServiceName: ss.GRPCSettings.ServiceName,
		ALPN:        ss.TLSSettings.ALPN,
		Insecure:    ss.TLSSettings.AllowInsecure,
	}
	if n.SNI == "" {
		n.SNI = ss.TLSSettings.ServerName
	}
	if h, ok := ss.WSSettings.Headers["Host"]; ok {
		n.Host = h
	}
	if ss.XHTTPSettings.Path != "" {
		n.Path = ss.XHTTPSettings.Path
		n.Host = ss.XHTTPSettings.Host
	}

	switch ob.Protocol {
	case "vless":
		n.Proto = model.ProtoVLESS
		n.UUID, n.Flow = user.UUID, user.Flow
	case "vmess":
		n.Proto = model.ProtoVMess
		n.UUID, n.Method = user.UUID, "auto"
	case "trojan":
		n.Proto = model.ProtoTrojan
		n.Password = user.Password
	case "shadowsocks":
		n.Proto = model.ProtoSS
		n.Method, n.Password = user.Method, user.Password
	case "socks":
		n.Proto = model.ProtoSocks5
		n.UUID, n.Password = user.User, user.Pass
	case "hysteria", "hysteria2":
		// hysteria v1 и v2 различаются транспортом, но в канонической
		// модели оба ложатся в hysteria2: ядро mihomo принимает обе формы
		// полем type=hysteria2 + version.
		n.Proto = model.ProtoHysteria2
		n.Password = user.Password
	case "tuic":
		n.Proto = model.ProtoTuic
		n.UUID, n.Password = user.UUID, user.Password
	case "anytls":
		n.Proto = model.ProtoAnyTLS
		n.Password = user.Password
	default:
		return nil, fmt.Errorf("xray: unsupported protocol %q", ob.Protocol)
	}
	return n, nil
}

// xrayUser — учётные данные из settings блока конкретного протокола.
type xrayUser struct {
	UUID, Flow, Password, Method, User, Pass string
}

// xrayEndpoint достаёт адрес, порт и учётные данные из settings.
// Форма settings зависит от протокола и разбирается через map, потому что
// у разных протоколов разные имена полей в одном и том же месте структуры.
func xrayEndpoint(ob xrayOutbound) (string, int, xrayUser, error) {
	var user xrayUser

	if vnext, ok := ob.Settings["vnext"].([]any); ok && len(vnext) > 0 {
		first, _ := vnext[0].(map[string]any)
		addr, _ := first["address"].(string)
		port := anyToInt(first["port"])
		if users, ok := first["users"].([]any); ok && len(users) > 0 {
			u, _ := users[0].(map[string]any)
			user.UUID, _ = u["id"].(string)
			user.Flow, _ = u["flow"].(string)
			user.Password, _ = u["password"].(string)
		}
		if addr == "" || port == 0 {
			return "", 0, user, fmt.Errorf("xray: vnext without address or port")
		}
		return addr, port, user, nil
	}

	if servers, ok := ob.Settings["servers"].([]any); ok && len(servers) > 0 {
		first, _ := servers[0].(map[string]any)
		addr, _ := first["address"].(string)
		port := anyToInt(first["port"])
		user.Password, _ = first["password"].(string)
		user.Method, _ = first["method"].(string)
		user.User, _ = first["user"].(string)
		if users, ok := first["users"].([]any); ok && len(users) > 0 {
			u, _ := users[0].(map[string]any)
			if user.Password == "" {
				user.Password, _ = u["password"].(string)
			}
			if user.User == "" {
				user.User, _ = u["username"].(string)
			}
		}
		if addr == "" || port == 0 {
			return "", 0, user, fmt.Errorf("xray: servers entry without address or port")
		}
		return addr, port, user, nil
	}

	// Плоская форма: Xray кладёт address и port прямо в settings. Так
	// разложен hysteria в бандлах pro1link — не в vnext и не в servers, а
	// рядом с полем version. Пароль там же, в hysteriaSettings.auth.
	if addr, _ := ob.Settings["address"].(string); addr != "" {
		port := anyToInt(ob.Settings["port"])
		if port == 0 {
			return "", 0, user, fmt.Errorf("xray: flat settings for %q have no port", addr)
		}
		user.Password, _ = ob.StreamSettings.HysteriaSettings.Auth.(string)
		if user.Password == "" {
			user.Password, _ = ob.Settings["auth"].(string)
		}
		return addr, port, user, nil
	}

	return "", 0, user, fmt.Errorf("xray: settings of protocol %q have no vnext, servers or flat address", ob.Protocol)
}

// anyToInt принимает число и строку: Xray пишет порт числом, а некоторые
// генераторы — строкой.
func anyToInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		n, err := strconv.Atoi(t)
		if err != nil {
			return 0
		}
		return n
	}
	return 0
}
