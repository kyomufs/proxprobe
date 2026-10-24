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
	switch strings.ToLower(scheme) {
	case "vless":
		return parseVLESS(line)
	case "vmess":
		return parseVMess(line)
	case "trojan":
		return parseTrojan(line)
	case "ss":
		return parseSS(line)
	case "socks5", "socks":
		return parseSocks5(line)
	case "hysteria2", "hy2":
		return parseHysteria2(line)
	case "tuic":
		return parseTuic(line)
	case "anytls":
		return parseAnyTLS(line)
	}
	return nil, fmt.Errorf("unsupported scheme %q", scheme)
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
