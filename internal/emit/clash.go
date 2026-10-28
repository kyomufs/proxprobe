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
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/kyomufs/proxprobe/internal/model"
)

// Имена выходных файлов. Лежат рядом, чтобы имя в switch и подпись в
// документации не разъезжались.
const (
	MergedClashName = "merged.yaml"
	SortedClashName = "sorted.yaml"
)

// WriteAll пишет все запрошенные форматы в каталог dir.
//
// Цели называются по смыслу, а не по имени файла: merged — все узлы,
// sorted — только живые по возрастанию задержки. Файлы — merged.yaml и
// sorted.yaml соответственно.
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
		case "merged":
			name = MergedClashName
			body, err = Clash(nodes)
		case "sorted":
			name = SortedClashName
			body, err = Sorted(nodes)
		default:
			return written, fmt.Errorf("emit: unknown target %q (supported: merged, sorted)", target)
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
	return buildClash(nodes)
}

// Sorted генерирует профиль только из узлов, прошедших проверку, по
// возрастанию задержки.
//
// Отбор идёт по статусу, а не по «delay_ms > 0»: у узла со статусом
// throttled задержка тоже измерена (цель ответила 429), и по старому
// условию он попал бы в профиль как живой. Статус различает «годен» и
// «ответил, но не пускает».
func Sorted(nodes []model.Node) ([]byte, error) {
	alive := make([]model.Node, 0, len(nodes))
	for _, n := range nodes {
		if n.Raw == nil {
			continue
		}
		status, hasStatus := n.Raw["status"].(string)
		if hasStatus {
			if status == model.StatusAlive {
				alive = append(alive, n)
			}
			continue
		}
		// Результаты старых прогонов поля status не имеют: для них
		// сохраняется прежнее условие по задержке, иначе обновление
		// утилиты опустошило бы профиль.
		if d, ok := n.Raw["delay_ms"].(float64); ok && d > 0 {
			alive = append(alive, n)
		}
	}
	sort.SliceStable(alive, func(i, j int) bool {
		return delayOf(alive[i]) < delayOf(alive[j])
	})
	return buildClash(alive)
}

// buildClash собирает профиль: узлы, плоская группа-селектор, группы по
// странам и AUTO.
//
// Группы плоские, а не вложенные: вложенные селекторы в mihomo ломают
// переключение в клиентах и превращают профиль в «кашу» — раскрыть, что
// внутри «Нидерланды», можно только в редакторе. Здесь страна — отдельная
// группа, а PROXY выбирает между ней и AUTO.
func buildClash(nodes []model.Node) ([]byte, error) {
	doc := clashDoc{
		MixedPort:       7890,
		AllowLan:        false,
		Mode:            "rule",
		LogLevel:        "info",
		ExternalControl: "127.0.0.1:9090",
		Rules:           []string{"MATCH,PROXY"},
	}

	// Имена занимаются в ОДНОМ пространстве: у mihomo прокси и группа лежат
	// в общем словаре, и узел, названный как группа, делает конфиг циклом.
	//
	// В публичных подписках имя узла — это реклама канала («https://t.me/X»)
	// или слово, из которого countryOf делает группу («Авто», «Другое»).
	// Тогда клиент получает "loop is detected in ProxyGroup" и не грузит
	// профиль ЦЕЛИКОМ. Поэтому имена групп занимаются заранее, до первого
	// узла, и узел, претендующий на занятое имя, получает суффикс.
	used := map[string]int{}
	reserved := reservedNames(nodes)
	for _, name := range reserved {
		used[name]++
	}

	names := make([]string, 0, len(nodes))
	byCountry := map[string][]string{}
	var countryOrder []string

	for _, n := range nodes {
		proxy, err := proxyForClash(n)
		if err != nil {
			continue
		}
		// Имена уникализируются: ядро отвергает ВЕСЬ конфиг, если два
		// прокси названы одинаково, а в подписках повтор названий —
		// норма. Дедуп по ID не спасает: это разные серверы.
		name := uniqueName(n.Name, used)
		proxy["name"] = name
		doc.Proxies = append(doc.Proxies, proxy)
		names = append(names, name)

		country := countryOf(n.Name)
		if _, seen := byCountry[country]; !seen {
			countryOrder = append(countryOrder, country)
		}
		byCountry[country] = append(byCountry[country], name)
	}

	// Пустой профиль — не ошибка: sorted.yaml после прогона без живых узлов
	// должен остаться файлом, который клиент примет, а не исчезнуть с
	// ошибкой экспорта. Ядро принимает конфиг с DIRECT/REJECT в группе.
	if len(names) == 0 {
		doc.ProxyGroups = []map[string]any{{
			"name":    "PROXY",
			"type":    "select",
			"proxies": []string{"DIRECT"},
		}}
		return marshalYAML(doc)
	}

	doc.ProxyGroups = append(doc.ProxyGroups, map[string]any{
		"name":      "AUTO",
		"type":      "url-test",
		"proxies":   names,
		"url":       "https://www.gstatic.com/generate_204",
		"interval":  300,
		"tolerance": 50,
	})

	// Группы по странам только там, где реально больше одного узла:
	// группа из одного узла не даёт выбора и только засоряет список.
	sort.SliceStable(countryOrder, func(i, j int) bool {
		return byCountry[countryOrder[i]][0] < byCountry[countryOrder[j]][0]
	})
	for _, country := range countryOrder {
		members := byCountry[country]
		if len(members) < 2 {
			continue
		}
		doc.ProxyGroups = append(doc.ProxyGroups, map[string]any{
			"name":      country,
			"type":      "url-test",
			"proxies":   members,
			"url":       "https://www.gstatic.com/generate_204",
			"interval":  300,
			"tolerance": 50,
		})
	}

	top := []string{"AUTO"}
	for _, country := range countryOrder {
		if len(byCountry[country]) >= 2 {
			top = append(top, country)
		}
	}
	top = append(top, names...)
	doc.ProxyGroups = append([]map[string]any{{
		"name":    "PROXY",
		"type":    "select",
		"proxies": top,
	}}, doc.ProxyGroups...)

	return marshalYAML(doc)
}

// ReservedGroupNames — имена групп, которые профиль объявляет всегда.
// Нужны, чтобы имя узла не совпало с ними (см. reservedNames).
const (
	ProxyGroupName = "PROXY"
	AutoGroupName  = "AUTO"
)

// reservedNames возвращает имена групп, которые появятся в профиле для этих
// узлов.
//
// Считать их заранее приходится потому, что страна узла известна только
// после разбора имени, а имя узла зависит от того, занято ли уже её имя.
// Порядок «сначала все группы, потом все узлы» разрывает эту петлю.
//
// Группы по странам создаются только при двух и более узлах: группа из
// одного узла не даёт выбора. Список дублирует условие из buildClash
// намеренно — это цена вычисления имён до их присвоения.
func reservedNames(nodes []model.Node) []string {
	countries := map[string]int{}
	for _, n := range nodes {
		if _, err := proxyForClash(n); err != nil {
			continue
		}
		countries[countryOf(n.Name)]++
	}

	out := []string{ProxyGroupName, AutoGroupName}
	for country, count := range countries {
		if count >= 2 {
			out = append(out, country)
		}
	}
	return out
}

// delayOf возвращает замер задержки, положенный в Raw.
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

// countryOf вынимает страну из имени узла.
//
// Имена в подписках — «🇳🇱 Нидерланды TURBO #4», «🇪🇺 🎮 Авто | Белые
// списки» или «Нидерланды · Aeza СПб». Флаг-эмодзи может отсутствовать, а
// перед названием страны часто стоят служебные значки (⚡️, 🎮, 💎). Поэтому
// страна — первое слово, в котором есть буквы, а не первое слово вообще:
// иначе группами становились бы «🎮» и «⚡️».
func countryOf(name string) string {
	cleaned := strings.TrimSpace(stripFlags(name))
	if cleaned == "" {
		return "Другое"
	}
	for _, sep := range []string{" · ", " | ", " — ", " - "} {
		if idx := strings.Index(cleaned, sep); idx > 0 {
			cleaned = strings.TrimSpace(cleaned[:idx])
			break
		}
	}
	for _, word := range strings.Fields(cleaned) {
		if hasLetters(word) {
			return word
		}
	}
	return "Другое"
}

// hasLetters сообщает, есть ли в слове буквы, а не только значки и цифры.
func hasLetters(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

// stripFlags убирает региональные эмодзи-флаги (U+1F1E6..U+1F1FF).
func stripFlags(s string) string {
	var out strings.Builder
	for _, r := range s {
		if r >= 0x1F1E6 && r <= 0x1F1FF {
			continue
		}
		if unicode.IsSpace(r) && out.Len() == 0 {
			continue
		}
		out.WriteRune(r)
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
