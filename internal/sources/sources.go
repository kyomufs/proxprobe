// Package sources читает список подписок из YAML.
//
// Формат подписки здесь не указывается: один и тот же адрес отдаёт разное
// в зависимости от User-Agent, поэтому вид определяется по содержимому
// (internal/detect), а не по записи в конфиге.
package sources

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Source — одна подписка.
//
// UA нужен источникам, которые выбирают формат по клиенту: pro1link отдаёт
// Clash для clash-клиента и base64-список для v2rayNG. Пустое значение —
// DefaultUA из internal/fetch.
//
// Headers — заголовки, без которых источник отдаёт заглушку вместо узлов:
// панели с привязкой к устройству требуют что-то вроде x-hwid и без него
// возвращают два рекламных узла на 0.0.0.0:1. UA из поля выше применяется
// последним, чтобы не спорить с ua.
type Source struct {
	// ID — имя источника в отчёте и дампе. Пусто — берётся хост.
	ID       string            `yaml:"id,omitempty"`
	URL      string            `yaml:"url"`
	UA       string            `yaml:"ua,omitempty"`
	Insecure bool              `yaml:"insecure,omitempty"`
	Headers  map[string]string `yaml:"headers,omitempty"`
}

// File — корень sources.yaml.
type File struct {
	Sources []Source `yaml:"sources"`
}

// Load читает и проверяет sources.yaml.
//
// Разбор строгий: неизвестное поле — ошибка, а не тихо проигнорированная
// настройка. Конфиг с опечаткой в имени поля выглядел рабочим и молча
// отдавал заглушку вместо узлов.
//
// Повторяющийся URL схлопывается: две записи с одним адресом — это одна и
// та же подписка, и качать её дважды незачем.
func Load(path string) ([]Source, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sources: cannot read %s: %w", path, err)
	}

	var file File
	dec := yaml.NewDecoder(strings.NewReader(string(body)))
	dec.KnownFields(true)
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("sources: %s is not valid YAML: %w", path, err)
	}
	if len(file.Sources) == 0 {
		return nil, fmt.Errorf("sources: %s declares no sources", path)
	}

	seen := map[string]bool{}
	out := make([]Source, 0, len(file.Sources))
	for i, s := range file.Sources {
		raw := strings.TrimSpace(s.URL)
		if raw == "" {
			return nil, fmt.Errorf("sources: entry %d has no url", i+1)
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("sources: entry %d has unusable url %q", i+1, raw)
		}
		for name := range s.Headers {
			if strings.TrimSpace(name) == "" || strings.ContainsAny(name, " :\t\r\n") {
				return nil, fmt.Errorf("sources: entry %d has invalid header name %q", i+1, name)
			}
		}
		key := u.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		s.URL = key
		out = append(out, s)
	}
	return out, nil
}

// Name — короткое имя источника для отчёта и дампа: id, а если его нет —
// хост без www.
func (s Source) Name() string {
	if id := strings.TrimSpace(s.ID); id != "" {
		return id
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.Hostname() == "" {
		return "source"
	}
	return strings.TrimPrefix(u.Hostname(), "www.")
}

// HeaderList возвращает заголовки в стабильном порядке: одинаковый запрос
// между прогонами проще сравнивать в логах.
func (s Source) HeaderList() [][2]string {
	names := make([]string, 0, len(s.Headers))
	for name := range s.Headers {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([][2]string, 0, len(names))
	for _, name := range names {
		out = append(out, [2]string{http.CanonicalHeaderKey(name), s.Headers[name]})
	}
	return out
}
