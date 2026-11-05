// Package parse превращает входные форматы подписок в канонические узлы.
//
// Пакет ничего не знает ни о сети, ни о ядрах: на вход тело подписки, на
// выход []model.Node и список строк, которые разобрать не удалось.
package parse

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/kyomufs/proxprobe/internal/model"
)

// Skip — строка, которую разобрать не удалось. Причина сохраняется, чтобы
// молчаливая потеря данных была невозможна.
type Skip struct {
	Line   string
	Reason string
}

// Result — итог разбора одной подписки.
type Result struct {
	Nodes []model.Node
	Skips []Skip
}

func (r *Result) skip(line, reason string) {
	if len(line) > 200 {
		line = line[:200] + "…"
	}
	r.Skips = append(r.Skips, Skip{Line: line, Reason: reason})
}

// Links разбирает построчный список share-ссылок.
//
// Строки, не похожие на ссылку (заголовки, комментарии, пустые), молча
// пропускаются: в реальных подписках они есть и это не ошибка. Строка,
// похожая на ссылку, но не разобранная, попадает в Skips.
func Links(body []byte, source string) *Result {
	res := &Result{}
	for _, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if !strings.Contains(line, "://") {
			continue
		}
		node, err := ParseLink(line)
		if err != nil {
			res.skip(line, err.Error())
			continue
		}
		node.Source = []string{source}
		node.Raw = map[string]any{"link": line}
		node.Finalize()
		res.Nodes = append(res.Nodes, *node)
	}
	return res
}

// ParseLink разбирает одну share-ссылку любого поддерживаемого протокола.
//
// Перед разбором из строки снимается HTML-экранирование: источник
// goida-vpn-configs отдаёт ссылки из markdown-генератора, где разделитель
// параметров записан как &amp;. Без этого QueryUnescape склеивает соседние
// параметры в один (path становится "X&amp;fp=qq"), и поля теряются.
func ParseLink(line string) (*model.Node, error) {
	line = unescapeHTMLEntities(line)
	scheme, _, ok := strings.Cut(line, "://")
	if !ok {
		return nil, fmt.Errorf("not a share link")
	}
	var (
		node *model.Node
		err  error
	)
	switch strings.ToLower(scheme) {
	case "vless":
		node, err = parseVLESS(line)
	case "vmess":
		node, err = parseVMess(line)
	case "trojan":
		node, err = parseTrojan(line)
	case "ss":
		node, err = parseSS(line)
	case "socks5", "socks":
		node, err = parseSocks5(line)
	case "hysteria2", "hy2":
		node, err = parseHysteria2(line)
	case "tuic":
		node, err = parseTuic(line)
	case "anytls":
		node, err = parseAnyTLS(line)
	default:
		return nil, fmt.Errorf("unsupported scheme %q", scheme)
	}
	if err != nil {
		return nil, err
	}
	if err := checkEndpoint(node.Server); err != nil {
		return nil, err
	}
	return node, nil
}

// placeholderServers — адреса из шаблонов и примеров. Такой «сервер» не
// подключается никогда и только засоряет профиль мёртвой строкой.
var placeholderServers = map[string]bool{
	"0.0.0.0": true, "127.0.0.1": true, "::": true, "::1": true,
	"localhost": true, "example.com": true, "example.org": true,
	"example.net": true,
}

// checkEndpoint отбраковывает пустые и заведомо нерабочие адреса.
func checkEndpoint(server string) error {
	s := strings.ToLower(strings.TrimSpace(server))
	if s == "" {
		return fmt.Errorf("empty server address")
	}
	if placeholderServers[s] {
		return fmt.Errorf("placeholder server %q", s)
	}
	if strings.HasSuffix(s, ".invalid") || strings.HasSuffix(s, ".example") ||
		strings.HasSuffix(s, ".test") {
		return fmt.Errorf("placeholder server %q", s)
	}
	return nil
}

// decodeFragment превращает percent-encoded фрагмент ссылки в имя узла.
func decodeFragment(fragment string) string {
	if fragment == "" {
		return ""
	}
	if decoded, err := urlUnescape(fragment); err == nil {
		return decoded
	}
	return fragment
}

// b64decode пытается декодировать строку в обоих вариантах padding,
// а также в URL-safe алфавите: источники используют их вперемешку.
func b64decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	candidates := []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	}
	var lastErr error
	for _, enc := range candidates {
		if decoded, err := enc.DecodeString(s); err == nil {
			return decoded, nil
		} else {
			lastErr = err
		}
	}
	return nil, fmt.Errorf("base64 decode failed: %w", lastErr)
}

// htmlEntities — только те сущности, которые реально встречаются в
// подписках. Полный html.UnescapeString не нужен и опасен: он превратил бы
// легитимные &copy; в тексте имени узла в ©.
var htmlEntities = strings.NewReplacer(
	"&amp;", "&",
	"&#38;", "&",
	"&#x26;", "&",
)

// unescapeHTMLEntities снимает HTML-экранирование с share-ссылки.
// Если после снятия в строке появился "&", которого не было, — снимаем
// экранирование повторно: часть источников отдаёт двойное экранирование.
func unescapeHTMLEntities(line string) string {
	if !strings.Contains(line, "&") {
		return line
	}
	out := htmlEntities.Replace(line)
	if strings.Count(out, "&") != strings.Count(line, "&") {
		out = htmlEntities.Replace(out)
	}
	return out
}
