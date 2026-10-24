package probe

import (
	"crypto/tls"

	"github.com/kyomufs/proxprobe/internal/model"
)

// ssCipherAliases приводит имена шифров Shadowsocks к тем, которые знает
// ядро mihomo.
//
// Источник proxypool отдаёт sing-box-конфиг, а sing-box и mihomo называют
// один и тот же шифр по-разному: chacha20-poly1305 против
// chacha20-ietf-poly1305. Без приведения ядро отвечает
//
//	"cipher: chacha20-poly1305 initialize error: unknown method"
//
// и не поднимается целиком.
var ssCipherAliases = map[string]string{
	"chacha20-poly1305":       "chacha20-ietf-poly1305",
	"chacha20":                "chacha20-ietf",
	"xchacha20-poly1305":      "xchacha20-ietf-poly1305",
	"aes-128-gcm-siv":         "aead_aes_128_gcm",
	"aes-256-gcm-siv":         "aead_aes_256_gcm",
	"2022-blake3-aes-128-gcm": "2022-blake3-aes-128-gcm",
}

// NormaliseCipher возвращает имя шифра в нотации ядра.
func NormaliseCipher(method string) string {
	if alias, ok := ssCipherAliases[method]; ok {
		return alias
	}
	return method
}

// CoreCompatible сообщает, можно ли отдать узел ядру mihomo.
//
// Одна запись, которую ядро не примет, роняет загрузку ВСЕГО конфига:
// mihomo разбирает файл целиком и падает на первой ошибке. Поэтому узлы
// проверяются здесь, а не выясняются по факту отказа ядра.
func CoreCompatible(n model.Node) (bool, string) {
	if !model.SupportedByMihomo(n.Proto) {
		return false, "protocol not supported by core"
	}
	if n.Server == "" || n.Port == 0 {
		return false, "no endpoint"
	}
	switch n.Proto {
	case model.ProtoVLESS, model.ProtoVMess:
		if n.UUID == "" {
			return false, "missing uuid"
		}
	case model.ProtoTrojan, model.ProtoHysteria2:
		if n.Password == "" {
			return false, "missing password"
		}
	case model.ProtoSS:
		if n.Method == "" || n.Password == "" {
			return false, "missing cipher or password"
		}
	case model.ProtoTuic:
		if n.UUID == "" || n.Password == "" {
			return false, "missing uuid or password"
		}
	}
	// reality без публичного ключа ядро принимает, но соединение не встанет;
	// такие узлы всё равно не пройдут проверку, и тратить на них время ядра
	// незачем.
	if n.Security == model.SecReality && n.PublicKey == "" {
		return false, "reality without public key"
	}
	return true, ""
}

// Result — итог реальной проверки узла через туннель.
type Result struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Server  string  `json:"server"`
	Port    int     `json:"port"`
	Proto   string  `json:"proto"`
	DelayMs float64 `json:"delay_ms"`
	OK      bool    `json:"ok"`
	Error   string  `json:"error,omitempty"`
	Via     string  `json:"via,omitempty"` // "socks" или "rest"
}

// insecureTLS возвращает конфигурацию TLS для проб.
//
// Проверка цепочки отключена осознанно: через чужой узел идёт только запрос
// к эталонному URL, секретов в нём нет, а разбор цепочки на чужой стороне
// даёт недостоверные отказы. Публичные узлы регулярно ломают цепочку, и
// «не проходит TLS» неотличимо от «узел мёртв».
func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}
