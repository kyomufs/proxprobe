// Package emit генерирует выходные файлы: подписку и отчёт.
//
// Подписка — то, что читает клиент; отчёт — то, что читает человек, когда
// узлов ожидалось больше.
package emit

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kyomufs/proxprobe/internal/model"
)

// Имена выходных файлов.
const (
	SubFile    = "sub.yaml"
	ReportFile = "report.txt"
)

// testURL — цель проверки в группах клиента. generate_204 отвечает пустым
// телом и кодом 204, поэтому замер не зависит от размера страницы.
const testURL = "https://www.gstatic.com/generate_204"

// Имена групп. PROXY — то, что выбирает клиент по умолчанию, AUTO — лучший
// узел по задержке.
const (
	ProxyGroupName = "PROXY"
	AutoGroupName  = "AUTO"
)

// clashDoc — итоговый профиль.
//
// Здесь нет mixed-port, mode и dns: файл подписки импортируется в клиент, у
// которого эти настройки свои. Лишние поля переопределили бы их молча.
type clashDoc struct {
	Proxies     []map[string]any `yaml:"proxies"`
	ProxyGroups []map[string]any `yaml:"proxy-groups"`
	Rules       []string         `yaml:"rules"`
}

// Subscription собирает профиль из уже отобранных и отсортированных узлов.
//
// Порядок узлов сохраняется: main сортирует живые по задержке, и клиент
// видит их в том же порядке.
func Subscription(nodes []model.Node) ([]byte, error) {
	doc := clashDoc{
		Proxies: make([]map[string]any, 0, len(nodes)),
		Rules:   []string{"MATCH," + ProxyGroupName},
	}

	// Имена групп занимаются ДО узлов: у mihomo прокси и группа лежат в
	// одном словаре, и узел, названный PROXY, делает конфиг циклом
	// ("loop is detected in ProxyGroup"). Тогда клиент не грузит профиль
	// целиком.
	used := map[string]int{ProxyGroupName: 1, AutoGroupName: 1}
	names := make([]string, 0, len(nodes))

	for _, n := range nodes {
		proxy, err := proxyForClash(n)
		if err != nil {
			continue
		}
		// Имена уникализируются: ядро отвергает весь конфиг, если два
		// прокси названы одинаково, а в публичных подписках повтор названий
		// — норма.
		name := uniqueName(n.Name, used)
		proxy["name"] = name
		doc.Proxies = append(doc.Proxies, proxy)
		names = append(names, name)
	}

	if len(names) == 0 {
		// Пустой профиль остаётся валидным: клиент принимает группу с
		// DIRECT, а не падает на импорте.
		doc.ProxyGroups = []map[string]any{{
			"name":    ProxyGroupName,
			"type":    "select",
			"proxies": []string{"DIRECT"},
		}}
		return marshalYAML(doc)
	}

	top := append([]string{AutoGroupName}, names...)
	doc.ProxyGroups = []map[string]any{
		{"name": ProxyGroupName, "type": "select", "proxies": top},
		{
			"name":      AutoGroupName,
			"type":      "url-test",
			"proxies":   names,
			"url":       testURL,
			"interval":  300,
			"tolerance": 50,
		},
	}
	return marshalYAML(doc)
}

// proxyForClash собирает запись прокси для Clash.
//
// Если узел пришёл из Clash-конфига, его исходная запись переиспользуется:
// так сохраняются поля, которых нет в модели (packet-encoding, udp).
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
	case model.ProtoAnyTLS:
		// anytls в mihomo требует явного клиентского отпечатка; без него
		// ядро отвергает узел, поэтому fingerprint обязателен.
		proxy["type"] = "anytls"
		proxy["password"] = n.Password
		if n.Fingerprint != "" {
			proxy["client-fingerprint"] = n.Fingerprint
		}
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

// marshalYAML сериализует структуру с отступом в 2 пробела.
//
// yaml.v3 экранирует всё вне ASCII, поэтому имена вида «🇸🇪 Швеция»
// превращаются в \U0001F1F8\U0001F1EA Швеция: файл валиден, но нечитаем, и
// клиенты показывают такой профиль как мусор. После кодирования
// escape-последовательности возвращаются к исходным символам — это
// разрешено в YAML и восстанавливается любым парсером.
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
	return []byte(unescapeUnicode(buf.String())), nil
}

// unescapeUnicode превращает \uXXXX и \UXXXXXXXX обратно в символы.
//
// Только внутри двойных кавычек: вне строк escape не имеет смысла, а
// трогать его там означало бы портить данные.
func unescapeUnicode(s string) string {
	var out strings.Builder
	out.Grow(len(s))

	inString := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' && (i == 0 || s[i-1] != '\\') {
			inString = !inString
			out.WriteByte(c)
			continue
		}
		if !inString || c != '\\' || i+1 >= len(s) {
			out.WriteByte(c)
			continue
		}
		n := s[i+1]
		var width int
		switch n {
		case 'u':
			width = 4
		case 'U':
			width = 8
		default:
			out.WriteByte(c)
			continue
		}
		if i+2+width > len(s) {
			out.WriteByte(c)
			continue
		}
		var r rune
		if _, err := fmt.Sscanf(s[i+2:i+2+width], "%X", &r); err != nil {
			out.WriteByte(c)
			continue
		}
		out.WriteRune(r)
		i += 1 + width
	}
	return out.String()
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
