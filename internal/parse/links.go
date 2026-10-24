package parse

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/kyomufs/proxprobe/internal/model"
)

func urlUnescape(s string) (string, error) { return url.QueryUnescape(s) }

// queryFirst возвращает первое непустое значение из списка ключей.
// Источники пишут один и тот же параметр по-разному: sni/serverName/peer.
func queryFirst(q url.Values, keys ...string) string {
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func queryBool(q url.Values, keys ...string) bool {
	for _, k := range keys {
		switch strings.ToLower(q.Get(k)) {
		case "1", "true", "yes":
			return true
		}
	}
	return false
}

func alpnList(q url.Values) []string {
	raw := queryFirst(q, "alpn")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// splitUserHost отделяет учётные данные от адреса в authority-части ссылки.
func splitUserHost(authority string) (user, hostport string, err error) {
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return "", "", fmt.Errorf("share link has no credentials section")
	}
	return authority[:at], authority[at+1:], nil
}

func parseVLESS(line string) (*model.Node, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("vless: missing uuid")
	}
	host, port, err := model.ParseEndpoint(u.Host)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	q := u.Query()

	n := &model.Node{
		Proto:       model.ProtoVLESS,
		Name:        decodeFragment(u.Fragment),
		Server:      host,
		Port:        port,
		UUID:        u.User.Username(),
		Network:     queryFirst(q, "type", "network"),
		Path:        queryFirst(q, "path"),
		Host:        queryFirst(q, "host"),
		ServiceName: queryFirst(q, "serviceName", "service_name"),
		Security:    queryFirst(q, "security"),
		SNI:         queryFirst(q, "sni", "serverName", "peer"),
		ALPN:        alpnList(q),
		Insecure:    queryBool(q, "allowInsecure", "insecure"),
		Fingerprint: queryFirst(q, "fp"),
		PublicKey:   queryFirst(q, "pbk"),
		ShortID:     queryFirst(q, "sid"),
		SpiderX:     queryFirst(q, "spx"),
		Flow:        queryFirst(q, "flow"),
	}
	if n.Network == "" {
		n.Network = model.NetTCP
	}
	// reality без явного pbk неработоспособен — сообщаем об этом честно,
	// а не выдаём узел, который не подключится.
	if n.Security == model.SecReality && n.PublicKey == "" {
		return nil, fmt.Errorf("vless: security=reality without pbk")
	}
	return n, nil
}

// vmessBody — раскодированное тело vmess-ссылки (base64 от JSON).
//
// Поля, которые генераторы пишут то числом, то строкой, то булевым,
// объявлены как any: жёсткий тип здесь роняет json.Unmarshal на всём теле,
// и узел теряется целиком. Реальные примеры: port как "443" и как 443,
// tls как "tls" и как false.
type vmessBody struct {
	Add  string `json:"add"`
	Port any    `json:"port"`
	ID   string `json:"id"`
	Aid  any    `json:"aid"`
	Scy  string `json:"scy"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  any    `json:"tls"`
	SNI  string `json:"sni"`
	ALPN string `json:"alpn"`
	FP   string `json:"fp"`
	PS   string `json:"ps"`
}

// tlsEnabled трактует поле tls в любом из встречающихся написаний:
// "tls", "true", true — включено; false, "false", "" — выключено.
func (v vmessBody) tlsEnabled() bool {
	switch t := v.TLS.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "tls") || strings.EqualFold(t, "true")
	}
	return false
}

// Port приходит и числом, и строкой — в зависимости от клиента, которым
// ссылку сгенерировали.
func (v vmessBody) port() (int, error) {
	switch p := v.Port.(type) {
	case float64:
		return int(p), nil
	case string:
		return strconv.Atoi(strings.TrimSpace(p))
	}
	return 0, fmt.Errorf("vmess: port has unexpected type %T", v.Port)
}

func parseVMess(line string) (*model.Node, error) {
	payload := strings.TrimPrefix(line, "vmess://")
	if i := strings.IndexAny(payload, "#?"); i >= 0 {
		payload = payload[:i]
	}
	raw, err := b64decode(payload)
	if err != nil {
		return nil, fmt.Errorf("vmess: %w", err)
	}

	var body vmessBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("vmess: body is not JSON: %w", err)
	}
	if body.Add == "" || body.ID == "" {
		return nil, fmt.Errorf("vmess: missing address or id")
	}
	port, err := body.port()
	if err != nil {
		return nil, err
	}

	n := &model.Node{
		Proto:       model.ProtoVMess,
		Name:        body.PS,
		Server:      body.Add,
		Port:        port,
		UUID:        body.ID,
		Method:      body.Scy,
		Network:     body.Net,
		Path:        body.Path,
		Host:        body.Host,
		Security:    model.SecNone,
		SNI:         body.SNI,
		Fingerprint: body.FP,
	}
	if body.tlsEnabled() {
		n.Security = model.SecTLS
	}
	if body.ALPN != "" {
		for _, a := range strings.Split(body.ALPN, ",") {
			if a = strings.TrimSpace(a); a != "" {
				n.ALPN = append(n.ALPN, a)
			}
		}
	}
	if n.Name == "" {
		n.Name = decodeFragment(strings.TrimPrefix(line, line[:strings.Index(line, "#")+1]))
	}
	if i := strings.Index(line, "#"); i >= 0 {
		n.Name = decodeFragment(line[i+1:])
	}
	return n, nil
}

func parseTrojan(line string) (*model.Node, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, fmt.Errorf("trojan: %w", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("trojan: missing password")
	}
	host, port, err := model.ParseEndpoint(u.Host)
	if err != nil {
		return nil, fmt.Errorf("trojan: %w", err)
	}
	q := u.Query()

	n := &model.Node{
		Proto:       model.ProtoTrojan,
		Name:        decodeFragment(u.Fragment),
		Server:      host,
		Port:        port,
		Password:    u.User.Username(),
		Network:     queryFirst(q, "type", "network"),
		Path:        queryFirst(q, "path"),
		Host:        queryFirst(q, "host"),
		ServiceName: queryFirst(q, "serviceName", "service_name"),
		Security:    queryFirst(q, "security"),
		SNI:         queryFirst(q, "sni", "serverName", "peer"),
		ALPN:        alpnList(q),
		Insecure:    queryBool(q, "allowInsecure", "insecure"),
		Fingerprint: queryFirst(q, "fp"),
		PublicKey:   queryFirst(q, "pbk"),
		ShortID:     queryFirst(q, "sid"),
	}
	if n.Security == "" {
		n.Security = model.SecTLS
	}
	return n, nil
}

// parseSS разбирает оба варианта ss-ссылки: SIP002
// (base64(method:password)@host:port) и legacy (целиком base64).
func parseSS(line string) (*model.Node, error) {
	body := strings.TrimPrefix(line, "ss://")
	name := ""
	if i := strings.Index(body, "#"); i >= 0 {
		name = decodeFragment(body[i+1:])
		body = body[:i]
	}
	// Параметры плагина отбрасываются: они не влияют на адрес и порт.
	if i := strings.Index(body, "/?"); i >= 0 {
		body = body[:i]
	}

	var userinfo, hostport string
	if at := strings.LastIndex(body, "@"); at >= 0 {
		userinfo = body[:at]
		hostport = body[at+1:]
		if decoded, err := b64decode(userinfo); err == nil {
			userinfo = string(decoded)
		}
	} else {
		decoded, err := b64decode(body)
		if err != nil {
			return nil, fmt.Errorf("ss: neither SIP002 nor legacy base64 form: %w", err)
		}
		at := strings.LastIndex(string(decoded), "@")
		if at < 0 {
			return nil, fmt.Errorf("ss: decoded body has no credentials section")
		}
		userinfo = string(decoded[:at])
		hostport = string(decoded[at+1:])
	}

	method, password, ok := strings.Cut(userinfo, ":")
	if !ok {
		return nil, fmt.Errorf("ss: credentials are not in method:password form")
	}
	host, port, err := model.ParseEndpoint(hostport)
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}

	return &model.Node{
		Proto:    model.ProtoSS,
		Name:     name,
		Server:   host,
		Port:     port,
		Method:   method,
		Password: password,
		Network:  model.NetTCP,
		Security: model.SecNone,
	}, nil
}

func parseSocks5(line string) (*model.Node, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, fmt.Errorf("socks5: %w", err)
	}
	host, port, err := model.ParseEndpoint(u.Host)
	if err != nil {
		return nil, fmt.Errorf("socks5: %w", err)
	}
	n := &model.Node{
		Proto:    model.ProtoSocks5,
		Name:     decodeFragment(u.Fragment),
		Server:   host,
		Port:     port,
		Network:  model.NetTCP,
		Security: model.SecNone,
	}
	if u.User != nil {
		n.UUID = u.User.Username() // в socks5 это логин; поле переиспользовано осознанно
		n.Password, _ = u.User.Password()
	}
	return n, nil
}

func parseHysteria2(line string) (*model.Node, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, fmt.Errorf("hysteria2: %w", err)
	}
	host, port, err := model.ParseEndpoint(u.Host)
	if err != nil {
		return nil, fmt.Errorf("hysteria2: %w", err)
	}
	q := u.Query()
	password := ""
	if u.User != nil {
		password = u.User.Username()
	}
	if password == "" {
		password = queryFirst(q, "password", "auth")
	}
	if password == "" {
		return nil, fmt.Errorf("hysteria2: missing password")
	}
	return &model.Node{
		Proto:    model.ProtoHysteria2,
		Name:     decodeFragment(u.Fragment),
		Server:   host,
		Port:     port,
		Password: password,
		Network:  model.NetQUIC,
		Security: model.SecTLS,
		SNI:      queryFirst(q, "sni", "peer"),
		ALPN:     alpnList(q),
		Insecure: queryBool(q, "insecure", "allowInsecure"),
		Path:     queryFirst(q, "obfs-password"), // obfs-пароль; отдельного поля в модели нет
		Host:     queryFirst(q, "obfs"),
	}, nil
}

func parseTuic(line string) (*model.Node, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, fmt.Errorf("tuic: %w", err)
	}
	host, port, err := model.ParseEndpoint(u.Host)
	if err != nil {
		return nil, fmt.Errorf("tuic: %w", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("tuic: missing uuid")
	}
	password, _ := u.User.Password()
	q := u.Query()
	return &model.Node{
		Proto:       model.ProtoTuic,
		Name:        decodeFragment(u.Fragment),
		Server:      host,
		Port:        port,
		UUID:        u.User.Username(),
		Password:    password,
		Network:     model.NetQUIC,
		Security:    model.SecTLS,
		SNI:         queryFirst(q, "sni", "peer"),
		ALPN:        alpnList(q),
		Insecure:    queryBool(q, "insecure", "allowInsecure"),
		Fingerprint: queryFirst(q, "fp"),
	}, nil
}

func parseAnyTLS(line string) (*model.Node, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, fmt.Errorf("anytls: %w", err)
	}
	host, port, err := model.ParseEndpoint(u.Host)
	if err != nil {
		return nil, fmt.Errorf("anytls: %w", err)
	}
	q := u.Query()
	password := ""
	if u.User != nil {
		password = u.User.Username()
	}
	return &model.Node{
		Proto:       model.ProtoAnyTLS,
		Name:        decodeFragment(u.Fragment),
		Server:      host,
		Port:        port,
		Password:    password,
		Network:     model.NetTCP,
		Security:    model.SecTLS,
		SNI:         queryFirst(q, "sni", "peer"),
		Insecure:    queryBool(q, "insecure", "allowInsecure"),
		ALPN:        alpnList(q),
		Fingerprint: queryFirst(q, "fp"),
	}, nil
}
