// Package model описывает каноническое представление сервера.
//
// Единственный источник правды внутри утилиты: любые входные форматы
// приводятся к Node, любые выходные генерируются из Node. Форматы между
// собой напрямую не конвертируются.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Протоколы, которые утилита понимает.
const (
	ProtoVLESS     = "vless"
	ProtoVMess     = "vmess"
	ProtoTrojan    = "trojan"
	ProtoSS        = "ss"
	ProtoSocks5    = "socks5"
	ProtoHysteria2 = "hysteria2"
	ProtoTuic      = "tuic"
	ProtoAnyTLS    = "anytls"
	ProtoUnknown   = "unknown"
)

// Известные транспорты.
const (
	NetTCP         = "tcp"
	NetWS          = "ws"
	NetGRPC        = "grpc"
	NetH2          = "h2"
	NetHTTPUpgrade = "httpupgrade"
	NetXHTTP       = "xhttp"
	NetQUIC        = "quic"
	NetHTTP        = "http"
)

// Виды защиты канала.
const (
	SecNone    = "none"
	SecTLS     = "tls"
	SecReality = "reality"
)

// Node — один сервер в каноническом виде.
//
// Raw хранит исходное представление по формату ("clash", "xray", "singbox")
// и, если была share-ссылка, ключ "link". Он нужен, чтобы обратный экспорт
// не терял поля, которых нет в этой структуре.
type Node struct {
	ID    string `json:"id"`
	Proto string `json:"proto"`
	Name  string `json:"name,omitempty"`

	Server string `json:"server"`
	Port   int    `json:"port"`

	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
	Method   string `json:"method,omitempty"`
	Flow     string `json:"flow,omitempty"`

	Network     string `json:"network,omitempty"`
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	ServiceName string `json:"service_name,omitempty"`

	Security    string   `json:"security,omitempty"`
	SNI         string   `json:"sni,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	Insecure    bool     `json:"insecure,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	PublicKey   string   `json:"public_key,omitempty"`
	ShortID     string   `json:"short_id,omitempty"`
	SpiderX     string   `json:"spider_x,omitempty"`

	Source []string       `json:"source,omitempty"`
	Raw    map[string]any `json:"raw,omitempty"`
}

// Credential возвращает секретную часть узла — то, что отличает два
// сервера с одинаковым адресом.
func (n *Node) Credential() string {
	switch n.Proto {
	case ProtoVLESS, ProtoVMess:
		return n.UUID
	case ProtoTrojan, ProtoHysteria2, ProtoAnyTLS:
		return n.Password
	case ProtoSS:
		return n.Method + ":" + n.Password
	case ProtoSocks5:
		return n.UUID + ":" + n.Password
	case ProtoTuic:
		return n.UUID + ":" + n.Password
	}
	return ""
}

// ComputeID собирает ключ дедупа.
//
// В ключ входит "отпечаток доверия" канала: у reality два узла на одном
// адресе с разными publicKey — это разные серверы, а не дубликаты.
//
// Регистр SNI нормализуется: источники пишут один и тот же хост и как
// example.com, и как EXAMPLE.com, и без нормализации один сервер получает
// два разных ID. PublicKey не нормализуется — это base64, регистр значим.
func (n *Node) ComputeID() string {
	trust := strings.ToLower(n.SNI)
	trust += "|" + n.PublicKey
	if n.ShortID != "" {
		trust += "|" + n.ShortID
	}
	parts := []string{
		n.Proto,
		strings.ToLower(n.Server),
		fmt.Sprint(n.Port),
		n.Credential(),
		n.Network,
		trust,
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return n.Proto + "|" + strings.ToLower(n.Server) + "|" + fmt.Sprint(n.Port) + "|" + hex.EncodeToString(sum[:6])
}

// Finalize заполняет ID и приводит поля к единому виду.
func (n *Node) Finalize() {
	n.Server = strings.TrimSpace(n.Server)
	n.Name = strings.TrimSpace(n.Name)
	n.Network = strings.ToLower(strings.TrimSpace(n.Network))
	n.Security = strings.ToLower(strings.TrimSpace(n.Security))
	if n.Network == "" {
		n.Network = NetTCP
	}
	if n.Security == "" {
		n.Security = SecNone
	}
	if n.Proto == ProtoSS || n.Proto == ProtoSocks5 || n.Proto == ProtoTrojan ||
		n.Proto == ProtoHysteria2 || n.Proto == ProtoTuic || n.Proto == ProtoAnyTLS {
		if n.Security == SecNone && n.Proto != ProtoSocks5 {
			// Эти протоколы всегда идут поверх TLS либо несут своё шифрование;
			// явный "none" у них означает "не указано".
			n.Security = SecTLS
		}
	}
	if n.Name == "" {
		n.Name = fmt.Sprintf("%s-%s:%d", n.Proto, n.Server, n.Port)
	}
	// CDN-узлы часто присылают ws-путь без ведущего слэша.
	if n.Path != "" && !strings.HasPrefix(n.Path, "/") {
		n.Path = "/" + n.Path
	}
	sort.Strings(n.ALPN)
	n.ID = n.ComputeID()
}

// FilledCount — сколько значимых полей заполнено. Используется при слиянии
// дубликатов: побеждает более полная запись.
func (n *Node) FilledCount() int {
	vals := []string{
		n.Name, n.UUID, n.Password, n.Method, n.Flow,
		n.Path, n.Host, n.ServiceName, n.SNI, n.Fingerprint,
		n.PublicKey, n.ShortID, n.SpiderX,
	}
	count := 0
	for _, v := range vals {
		if v != "" {
			count++
		}
	}
	count += len(n.ALPN)
	if n.Insecure {
		count++
	}
	return count
}

// ParseEndpoint разбирает "host:port" с учётом того, что host может быть
// IPv6-литералом в скобках.
func ParseEndpoint(hostport string) (string, int, error) {
	u, err := url.Parse("//" + hostport)
	if err != nil {
		return "", 0, err
	}
	host := u.Hostname()
	portStr := u.Port()
	if host == "" || portStr == "" {
		return "", 0, fmt.Errorf("cannot split endpoint %q into host and port", hostport)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return "", 0, fmt.Errorf("invalid port in %q: %w", hostport, err)
	}
	if port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("port out of range in %q", hostport)
	}
	return host, port, nil
}

// SupportedByMihomo говорит, умеет ли ядро mihomo работать с протоколом.
// Нужно, чтобы не отдавать в тестовый конфиг узел, который ядро отвергнет
// целиком.
func SupportedByMihomo(proto string) bool {
	switch proto {
	case ProtoVLESS, ProtoVMess, ProtoTrojan, ProtoSS,
		ProtoSocks5, ProtoHysteria2, ProtoTuic:
		return true
	}
	// anytls mihomo 1.19 умеет, но только с явным клиентским отпечатком;
	// в конфиг теста такой узел не пойдёт, чтобы не ломать загрузку ядра.
	return false
}
