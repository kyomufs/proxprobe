// Package sources читает описание подписок из YAML.
package sources

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Source — одна подписка.
//
// Формат здесь НЕ указывается: один и тот же URL отдаёт разные форматы в
// зависимости от User-Agent, поэтому источник описывает только то, как
// скачать данные, а вид определяется по содержимому.
type Source struct {
	ID      string            `yaml:"id"`
	URL     string            `yaml:"url"`
	UA      string            `yaml:"ua,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty"`
	// Insecure отключает проверку сертификата. Нужен там, где сервер отдаёт
	// неполную цепочку: у pro1link на этой машине curl без -k падает.
	Insecure bool `yaml:"insecure,omitempty"`
	// Enabled позволяет держать источник в файле, но не тянуть его.
	Enabled *bool `yaml:"enabled,omitempty"`
}

// File — содержимое sources.yaml.
type File struct {
	Sources []Source `yaml:"sources"`
}

// Load читает файл описания подписок.
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
	for i, s := range file.Sources {
		if s.ID == "" {
			return nil, fmt.Errorf("sources: entry %d has no id", i+1)
		}
		if seen[s.ID] {
			return nil, fmt.Errorf("sources: duplicate id %q", s.ID)
		}
		seen[s.ID] = true
		if s.URL == "" {
			return nil, fmt.Errorf("sources: %q has no url", s.ID)
		}
	}
	return file.Sources, nil
}

// Active возвращает только включённые источники.
func Active(all []Source) []Source {
	out := make([]Source, 0, len(all))
	for _, s := range all {
		if s.Enabled != nil && !*s.Enabled {
			continue
		}
		out = append(out, s)
	}
	return out
}
