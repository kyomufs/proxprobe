// Package emit генерирует выходные форматы из канонических узлов.
//
// Обратная конвертация опирается на Raw: если узел пришёл из Clash-конфига,
// его Clash-представление берётся как есть, а не восстанавливается из
// общих полей. Так round-trip не теряет поля, которых нет в модели.
package emit

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kyomufs/proxprobe/internal/model"
)

// WriteAll пишет все запрошенные форматы в каталог dir.
func WriteAll(dir string, nodes []model.Node, targets []string) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("emit: cannot create %s: %w", dir, err)
	}

	var written []string
	for _, target := range targets {
		var (
			name string
			body []byte
			err  error
		)
		switch target {
		case "clash":
			name = "clash.yaml"
			body, err = Clash(nodes)
		case "best":
			name = "best.yaml"
			body, err = Best(nodes)
		default:
			return written, fmt.Errorf("emit: unknown target %q (supported: clash, best)", target)
		}
		if err != nil {
			return written, fmt.Errorf("emit %s: %w", target, err)
		}

		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, body, 0o644); err != nil {
			return written, fmt.Errorf("emit: cannot write %s: %w", path, err)
		}
		written = append(written, path)
	}
	return written, nil
}

// clashDoc — структура итогового Clash-конфига.
//
// В отличие от тестового конфига для ядра, это полноценный профиль:
// с группами по источникам и правилом MATCH на первую группу.
type clashDoc struct {
	MixedPort       int              `yaml:"mixed-port"`
	AllowLan        bool             `yaml:"allow-lan"`
	Mode            string           `yaml:"mode"`
	LogLevel        string           `yaml:"log-level"`
	ExternalControl string           `yaml:"external-controller"`
	Proxies         []map[string]any `yaml:"proxies"`
	ProxyGroups     []map[string]any `yaml:"proxy-groups"`
	Rules           []string         `yaml:"rules"`
}

// Clash генерирует Clash-профиль со всеми узлами.
func Clash(nodes []model.Node) ([]byte, error) {
	doc := clashDoc{
		MixedPort:       7890,
		AllowLan:        false,
		Mode:            "rule",
		LogLevel:        "info",
		ExternalControl: "127.0.0.1:9090",
		Rules:           []string{"MATCH,PROXY"},
	}

	// Имена узлов уникализируются: mihomo отвергает ВЕСЬ конфиг, если два
	// прокси названы одинаково ("is the duplicate name"), а в публичных
	// подписках повторяющиеся имена — норма (разные серверы с одинаковым
	// названием локации). Дедуп по ID здесь не помогает: это разные серверы.
	used := map[string]int{}
	names := make([]string, 0, len(nodes))
	for _, n := range nodes {
		proxy, err := proxyForClash(n)
		if err != nil {
			// Узел, который Clash не примет, в профиль не попадает: иначе
			// весь конфиг не загрузится из-за одного сервера.
			continue
		}
		name := uniqueName(n.Name, used)
		proxy["name"] = name
		doc.Proxies = append(doc.Proxies, proxy)
		names = append(names, name)
	}

	doc.ProxyGroups = []map[string]any{
		{
			"name":    "PROXY",
			"type":    "select",
			"proxies": append([]string{"AUTO"}, names...),
		},
		{
			"name":      "AUTO",
			"type":      "url-test",
			"proxies":   names,
			"url":       "https://www.gstatic.com/generate_204",
			"interval":  300,
			"tolerance": 50,
		},
	}

	return marshalYAML(doc)
}

// Best генерирует профиль только из узлов, прошедших проверку, по
// возрастанию задержки.
func Best(nodes []model.Node) ([]byte, error) {
	alive := make([]model.Node, 0, len(nodes))
	for _, n := range nodes {
		if n.Raw != nil {
			if d, ok := n.Raw["delay_ms"].(float64); ok && d > 0 {
				alive = append(alive, n)
			}
		}
	}
	sort.SliceStable(alive, func(i, j int) bool {
		return delayOf(alive[i]) < delayOf(alive[j])
	})
	return Clash(alive)
}

func delayOf(n model.Node) float64 {
	if n.Raw == nil {
		return 1 << 30
	}
	if d, ok := n.Raw["delay_ms"].(float64); ok {
		return d
	}
	return 1 << 30
}

// proxyForClash собирает запись прокси для Clash.
//
// Если узел пришёл из Clash-конфига, возвращается его исходная запись с
// исправленным именем: так сохраняются поля, которых нет в модели
// (например, packet-encoding или udp-флаги).
func proxyForClash(n model.Node) (map[string]any, error) {
	if raw, ok := n.Raw["clash"].(map[string]any); ok && len(raw) > 0 {
		proxy := map[string]any{}
		for k, v := range raw {
			proxy[k] = v
		}
		proxy["name"] = n.Name
		return proxy, nil
	}

	proxy := map[string]any{
		"name":   n.Name,
		"server": n.Server,
		"port":   n.Port,
	}
	switch n.Proto {
	case model.ProtoVLESS:
		proxy["type"] = "vless"
		proxy["uuid"] = n.UUID
		if n.Flow != "" {
			proxy["flow"] = n.Flow
		}
	case model.ProtoVMess:
		proxy["type"] = "vmess"
		proxy["uuid"] = n.UUID
		proxy["alterId"] = 0
		proxy["cipher"] = orDefault(n.Method, "auto")
	case model.ProtoTrojan:
		proxy["type"] = "trojan"
		proxy["password"] = n.Password
	case model.ProtoSS:
		proxy["type"] = "ss"
		proxy["cipher"] = n.Method
		proxy["password"] = n.Password
	case model.ProtoSocks5:
		proxy["type"] = "socks5"
		if n.UUID != "" {
			proxy["username"] = n.UUID
			proxy["password"] = n.Password
		}
	case model.ProtoHysteria2:
		proxy["type"] = "hysteria2"
		proxy["password"] = n.Password
	case model.ProtoTuic:
		proxy["type"] = "tuic"
		proxy["uuid"] = n.UUID
		proxy["password"] = n.Password
	default:
		return nil, fmt.Errorf("clash: protocol %q has no mapping", n.Proto)
	}

	if n.Network == model.NetWS {
		wsOpts := map[string]any{"path": n.Path}
		if n.Host != "" {
			wsOpts["headers"] = map[string]string{"Host": n.Host}
		}
		proxy["network"] = "ws"
		proxy["ws-opts"] = wsOpts
	} else if n.Network == model.NetGRPC {
		proxy["network"] = "grpc"
		proxy["grpc-opts"] = map[string]any{"grpc-service-name": n.ServiceName}
	}

	switch n.Security {
	case model.SecTLS:
		proxy["tls"] = true
		if n.SNI != "" {
			proxy["servername"] = n.SNI
		}
	case model.SecReality:
		proxy["tls"] = true
		if n.SNI != "" {
			proxy["servername"] = n.SNI
		}
		reality := map[string]any{"public-key": n.PublicKey}
		if n.ShortID != "" {
			reality["short-id"] = n.ShortID
		}
		proxy["reality-opts"] = reality
		proxy["client-fingerprint"] = orDefault(n.Fingerprint, "chrome")
	}
	if len(n.ALPN) > 0 {
		proxy["alpn"] = n.ALPN
	}
	if n.Insecure {
		proxy["skip-cert-verify"] = true
	}
	return proxy, nil
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// marshalYAML сериализует структуру с отступом в 2 пробела и без
// выравнивания длинных ключей: так файл читается и стабильно диффится.
func marshalYAML(v any) ([]byte, error) {
	var buf strings.Builder
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

// uniqueName делает имя узла уникальным внутри профиля.
//
// Суффикс — не косметика: mihomo отказывается загружать конфиг целиком,
// если два прокси названы одинаково.
func uniqueName(name string, used map[string]int) string {
	count := used[name]
	used[name]++
	if count == 0 {
		return name
	}
	return fmt.Sprintf("%s #%d", name, count+1)
}
