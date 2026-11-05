// Package sources читает список подписок из YAML.
//
// Формат подписки здесь не указывается: один и тот же адрес отдаёт разное
// в зависимости от User-Agent, поэтому вид определяется по содержимому
// (internal/detect), а не по записи в конфиге.
package sources

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Source — одна подписка.
//
// UA нужен источникам, которые выбирают формат по клиенту: pro1link отдаёт
// Clash для clash-клиента и base64-список для v2rayNG. Пустое значение —
// DefaultUA из internal/fetch.
type Source struct {
	URL      string `yaml:"url"`
	UA       string `yaml:"ua,omitempty"`
	Insecure bool   `yaml:"insecure,omitempty"`
}

// File — корень sources.yaml.
type File struct {
	Sources []Source `yaml:"sources"`
}

// Load читает и проверяет sources.yaml.
//
// Повторяющийся URL схлопывается: две записи с одним адресом — это одна и
// та же подписка, и качать её дважды незачем.
func Load(path string) ([]Source, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sources: cannot read %s: %w", path, err)
	}

	var file File
	if err := yaml.Unmarshal(body, &file); err != nil {
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

// Name — короткое имя источника для отчёта и дампа: хост без www.
func (s Source) Name() string {
	u, err := url.Parse(s.URL)
	if err != nil || u.Hostname() == "" {
		return "source"
	}
	return strings.TrimPrefix(u.Hostname(), "www.")
}
