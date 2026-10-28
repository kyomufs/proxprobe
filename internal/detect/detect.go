// Package detect определяет формат подписки по её содержимому.
//
// Формат не выводится ни из расширения, ни из URL: один и тот же адрес
// pro1link отдаёт разные форматы в зависимости от User-Agent, а разные
// репозитории кладут одно и то же содержимое в .txt, .json и .yaml.
package detect

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"regexp"
)

// Format — распознанный вид подписки.
type Format string

const (
	// FormatLinks — построчный текст со share-ссылками (vless://, vmess://, ...).
	FormatLinks Format = "links"
	// FormatLinksB64 — то же, но тело закодировано base64.
	FormatLinksB64 Format = "links-b64"
	// FormatClash — YAML с секцией proxies:.
	FormatClash Format = "clash"
	// FormatXrayBundles — JSON-массив конфигов Xray, каждый со своими outbounds.
	FormatXrayBundles Format = "xray-bundles"
	// FormatXrayConfig — одиночный конфиг Xray (объект с outbounds).
	FormatXrayConfig Format = "xray-config"
	// FormatSingbox — конфиг sing-box (объект с outbounds[]).
	FormatSingbox Format = "singbox"
	// FormatUnknown — не распознано.
	FormatUnknown Format = "unknown"
)

var (
	linkSchemeRe = regexp.MustCompile(`(?m)^(vless|vmess|trojan|ss|ssr|socks5|socks|hysteria2|hy2|tuic|anytls)://`)
	base64Re     = regexp.MustCompile(`^[A-Za-z0-9+/=\s]+$`)
	proxiesRe    = regexp.MustCompile(`(?m)^\s*proxies\s*:`)
)

// Sniff возвращает формат и тело для дальнейшего разбора.
//
// Если вход оказался base64-обёрткой, вторым значением возвращается уже
// раскодированное тело: вызывающей стороне не нужно повторять эвристику.
func Sniff(body []byte) (Format, []byte) {
	if len(body) == 0 {
		return FormatUnknown, body
	}

	// JSON разбирается первым: у него однозначный признак, и он не может
	// быть ничем другим.
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) > 0 && (trimmed[0] == '[' || trimmed[0] == '{') {
		if f := sniffJSON(trimmed); f != FormatUnknown {
			return f, body
		}
	}

	// Ссылки в открытом виде.
	if linkSchemeRe.Match(body) {
		return FormatLinks, body
	}

	// Base64-обёртка. Признак берётся из практики: декодируем, если строка
	// целиком из base64-алфавита и результат похож на подписку.
	if decoded, ok := tryBase64(body); ok {
		return FormatLinksB64, decoded
	}

	// YAML с proxies: — как в открытом виде, так и внутри base64.
	if proxiesRe.Match(body) {
		return FormatClash, body
	}
	if decoded, ok := tryBase64(body); ok && proxiesRe.Match(decoded) {
		return FormatClash, decoded
	}

	return FormatUnknown, body
}

// sniffJSON различает три JSON-формы: массив бандлов Xray, одиночный конфиг
// Xray и конфиг sing-box.
func sniffJSON(body []byte) Format {
	if len(body) > 0 && body[0] == '[' {
		return FormatXrayBundles
	}

	var probe struct {
		Outbounds []struct {
			Type     string `json:"type"`
			Protocol string `json:"protocol"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return FormatUnknown
	}
	if len(probe.Outbounds) == 0 {
		return FormatUnknown
	}

	// У Xray outbound задаётся полем protocol (vless/vmess/freedom/...),
	// у sing-box — полем type (vless/vmess/selector/direct/...).
	singboxTypes := 0
	xrayProtocols := 0
	for _, o := range probe.Outbounds {
		if o.Type != "" {
			singboxTypes++
		}
		if o.Protocol != "" {
			xrayProtocols++
		}
	}
	switch {
	case singboxTypes > 0 && xrayProtocols == 0:
		return FormatSingbox
	case xrayProtocols > 0 && singboxTypes == 0:
		return FormatXrayConfig
	}
	return FormatUnknown
}

// tryBase64 декодирует тело, если оно целиком является base64-строкой, и
// результат похож на подписку.
//
// Проверка на "похожесть" обязательна: без неё произвольный текст из
// base64-алфавита (например, hex-подобный список) будет раскодирован в мусор.
func tryBase64(body []byte) ([]byte, bool) {
	compact := make([]byte, 0, len(body))
	for _, b := range body {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		}
		compact = append(compact, b)
	}
	if len(compact) == 0 || len(compact)%4 != 0 || !base64Re.Match(compact) {
		return nil, false
	}

	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(compact)))
	n, err := base64.StdEncoding.Decode(decoded, compact)
	if err != nil {
		// Padding бывает урезан; пробуем без него.
		decoded = make([]byte, base64.RawStdEncoding.DecodedLen(len(compact)))
		n, err = base64.RawStdEncoding.Decode(decoded, compact)
		if err != nil {
			return nil, false
		}
	}
	decoded = decoded[:n]

	if !linkSchemeRe.Match(decoded) && !proxiesRe.Match(decoded) {
		return nil, false
	}
	return decoded, true
}

// String нужен для читаемого вывода в отчёте.
func (f Format) String() string { return string(f) }
