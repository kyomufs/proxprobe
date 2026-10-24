package parse

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/kyomufs/proxprobe/internal/model"
)

// clashProxy — запись из секции proxies: Clash-конфига.
//
// Поля объявлены как map/any там, где источники расходятся: port приходит
// числом и строкой, reality-opts бывает и объектом, и отсутствует.
type clashProxy struct {
	Name           string         `yaml:"name"`
	Type           string         `yaml:"type"`
	Server         string         `yaml:"server"`
	Port           any            `yaml:"port"`
	UUID           string         `yaml:"uuid"`
	Password       string         `yaml:"password"`
	Cipher         string         `yaml:"cipher"`
	AlterID        any            `yaml:"alterId"`
	Network        string         `yaml:"network"`
	TLS            bool           `yaml:"tls"`
	SNI            string         `yaml:"servername"`
	SkipCertVerify bool           `yaml:"skip-cert-verify"`
	Flow           string         `yaml:"flow"`
	ClientFP       string         `yaml:"client-fingerprint"`
	WSOpts         map[string]any `yaml:"ws-opts"`
	GRPCOpts       map[string]any `yaml:"grpc-opts"`
	RealityOpts    struct {
		PublicKey string `yaml:"public-key"`
		ShortID   string `yaml:"short-id"`
	} `yaml:"reality-opts"`
	ALPN []string `yaml:"alpn"`
	// Прочее сохраняется как есть, чтобы экспорт не терял поля.
	Extra map[string]any `yaml:",inline"`
}

func (p clashProxy) port() (int, error) {
	switch v := p.Port.(type) {
	case int:
		return v, nil
	case float64:
		return int(v), nil
	case string:
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
			return 0, fmt.Errorf("clash: invalid port %q", v)
		}
		return n, nil
	}
	return 0, fmt.Errorf("clash: port has unexpected type %T", p.Port)
}

// Clash разбирает Clash-конфиг (секция proxies:).
//
// Если YAML не парсится целиком (в публичных подписках встречаются битые
// документы), применяется построчное выгрызание секции: это дешевле, чем
// терять всю подписку целиком.
func Clash(body []byte, source string) *Result {
	res := &Result{}

	proxies, err := clashProxies(body)
	if err != nil {
		res.skip(string(body[:min(len(body), 200)]), err.Error())
		return res
	}

	for _, p := range proxies {
		node, err := clashProxyToNode(p)
		if err != nil {
			res.skip(p.Name, err.Error())
			continue
		}
		node.Source = []string{source}
		node.Raw = map[string]any{"clash": clashProxyToMap(p)}
		node.Finalize()
		res.Nodes = append(res.Nodes, *node)
	}
	return res
}

// clashProxyToMap возвращает запись прокси в том виде, в каком её понимает
// ядро.
//
// Через JSON-маршалинг структуры этого делать НЕЛЬЗЯ: yaml-теги при этом не
// применяются, и в конфиг ядра уходят ключи Go-регистра ("Type", "Server",
// "Port"). Ядро отвечает "missing type" и не поднимается. Поэтому карта
// собирается вручную и только из тех полей, которые модель сохранила.
func clashProxyToMap(p clashProxy) map[string]any {
	proxy := map[string]any{
		"name":   p.Name,
		"type":   p.Type,
		"server": p.Server,
	}
	if port, err := p.port(); err == nil {
		proxy["port"] = port
	}

	// Extra несёт неразобранные поля записи (packet-encoding, udp, и т.п.) —
	// они переносятся как есть, иначе профиль для ядра теряет настройки.
	for k, v := range p.Extra {
		if _, taken := proxy[k]; !taken {
			proxy[k] = v
		}
	}

	switch p.Type {
	case "vless":
		proxy["uuid"] = p.UUID
		if p.Flow != "" {
			proxy["flow"] = p.Flow
		}
	case "vmess":
		proxy["uuid"] = p.UUID
		proxy["alterId"] = 0
		proxy["cipher"] = orDefault(p.Cipher, "auto")
	case "trojan", "hysteria2", "hysteria", "anytls":
		proxy["password"] = p.Password
	case "ss":
		proxy["cipher"] = p.Cipher
		proxy["password"] = p.Password
	case "socks5":
		if p.UUID != "" {
			proxy["username"] = p.UUID
			proxy["password"] = p.Password
		}
	case "tuic":
		proxy["uuid"] = p.UUID
		proxy["password"] = p.Password
	}

	if p.Network == "ws" && p.WSOpts != nil {
		proxy["network"] = "ws"
		proxy["ws-opts"] = p.WSOpts
	} else if p.Network == "grpc" && p.GRPCOpts != nil {
		proxy["network"] = "grpc"
		proxy["grpc-opts"] = p.GRPCOpts
	} else if p.Network != "" && p.Network != "tcp" {
		proxy["network"] = p.Network
	}

	if p.TLS {
		proxy["tls"] = true
	}
	if p.SNI != "" {
		proxy["servername"] = p.SNI
	}
	if p.RealityOpts.PublicKey != "" {
		reality := map[string]any{"public-key": p.RealityOpts.PublicKey}
		if p.RealityOpts.ShortID != "" {
			reality["short-id"] = p.RealityOpts.ShortID
		}
		proxy["reality-opts"] = reality
	}
	if p.ClientFP != "" {
		proxy["client-fingerprint"] = p.ClientFP
	}
	if len(p.ALPN) > 0 {
		proxy["alpn"] = p.ALPN
	}
	if p.SkipCertVerify {
		proxy["skip-cert-verify"] = true
	}
	return proxy
}

func clashProxies(body []byte) ([]clashProxy, error) {
	var doc struct {
		Proxies []clashProxy `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(body, &doc); err == nil && len(doc.Proxies) > 0 {
		return doc.Proxies, nil
	}

	// Запасной путь: построчно собрать блок proxies: и разобрать только его.
	block := extractProxiesBlock(body)
	if len(block) == 0 {
		return nil, fmt.Errorf("clash: no proxies section found")
	}
	var partial struct {
		Proxies []clashProxy `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(block, &partial); err != nil {
		return nil, fmt.Errorf("clash: proxies block is not valid YAML: %w", err)
	}
	return partial.Proxies, nil
}

// extractProxiesBlock достаёт секцию proxies: из документа, который целиком
// не разбирается. Блок кончается на первой строке верхнего уровня.
func extractProxiesBlock(body []byte) []byte {
	lines := bytes.Split(body, []byte("\n"))
	start := -1
	for i, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if bytes.Equal(trimmed, []byte("proxies:")) {
			start = i
			break
		}
	}
	if start < 0 {
		return nil
	}
	var out bytes.Buffer
	out.WriteString("proxies:\n")
	for _, line := range lines[start+1:] {
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && line[0] != '-' {
			break
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

func clashProxyToNode(p clashProxy) (*model.Node, error) {
	port, err := p.port()
	if err != nil {
		return nil, err
	}
	if p.Server == "" {
		return nil, fmt.Errorf("clash: %q has no server", p.Name)
	}

	n := &model.Node{
		Name:     p.Name,
		Server:   p.Server,
		Port:     port,
		Network:  p.Network,
		Security: model.SecNone,
		SNI:      p.SNI,
		Insecure: p.SkipCertVerify,
		Flow:     p.Flow,
		ALPN:     p.ALPN,
	}

	switch p.Type {
	case "vless":
		n.Proto = model.ProtoVLESS
		n.UUID = p.UUID
	case "vmess":
		n.Proto = model.ProtoVMess
		n.UUID = p.UUID
		n.Method = p.Cipher
		n.Fingerprint = p.ClientFP
	case "trojan":
		n.Proto = model.ProtoTrojan
		n.Password = p.Password
	case "ss":
		n.Proto = model.ProtoSS
		n.Method = p.Cipher
		n.Password = p.Password
	case "socks5":
		n.Proto = model.ProtoSocks5
		n.UUID = p.UUID
		n.Password = p.Password
	case "hysteria2", "hysteria":
		n.Proto = model.ProtoHysteria2
		n.Password = p.Password
	case "tuic":
		n.Proto = model.ProtoTuic
		n.UUID = p.UUID
		n.Password = p.Password
	case "anytls":
		n.Proto = model.ProtoAnyTLS
		n.Password = p.Password
	default:
		return nil, fmt.Errorf("clash: unsupported proxy type %q", p.Type)
	}

	if p.TLS {
		n.Security = model.SecTLS
	}
	if p.RealityOpts.PublicKey != "" {
		n.Security = model.SecReality
		n.PublicKey = p.RealityOpts.PublicKey
		n.ShortID = p.RealityOpts.ShortID
	}
	// Клиентский отпечаток у reality лежит в client-fingerprint, а не в fp.
	if n.Fingerprint == "" {
		n.Fingerprint = p.ClientFP
	}

	// ws-opts: path и заголовок Host. В Clash путь лежит вложенно.
	if p.WSOpts != nil {
		if path, ok := p.WSOpts["path"].(string); ok {
			n.Path = path
		}
		if headers, ok := p.WSOpts["headers"].(map[string]any); ok {
			if h, ok := headers["Host"].(string); ok {
				n.Host = h
			}
		}
	}
	if p.GRPCOpts != nil {
		if svc, ok := p.GRPCOpts["grpc-service-name"].(string); ok {
			n.ServiceName = svc
		}
	}
	return n, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// orDefault подставляет значение по умолчанию вместо пустой строки: ядро
// отвергает пустой cipher, а источники регулярно его не указывают.
func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
