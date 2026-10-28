package probe

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/kyomufs/proxprobe/internal/model"
)

// duplicateNameNodes — два РАЗНЫХ сервера с одинаковым именем: ровно то, что
// даёт публичная подписка (десятки узлов «🇳🇱»).
func duplicateNameNodes() []model.Node {
	mk := func(server string) model.Node {
		n := model.Node{
			Proto: model.ProtoVLESS, Name: "🇳🇱", Server: server, Port: 443,
			UUID: "11111111-2222-3333-4444-555555555555",
		}
		n.Finalize()
		return n
	}
	return []model.Node{mk("first.example.com"), mk("second.example.com"), mk("third.example.com")}
}

// TestWriteMihomoConfigReportsCoreNames закрывает дефект, из-за которого
// проба переключала селектор на «🇳🇱» для ВСЕХ дублей, тогда как в конфиге
// они назывались «🇳🇱», «🇳🇱 #2», «🇳🇱 #3». Ядро в таком случае переключается
// на первый узел, и вердикт с задержкой достаются чужому серверу.
func TestWriteMihomoConfigReportsCoreNames(t *testing.T) {
	nodes := duplicateNameNodes()
	cfg := Defaults()
	path := filepath.Join(t.TempDir(), "config.yaml")

	names, skipped, err := writeMihomoConfig(path, nodes, cfg)
	if err != nil {
		t.Fatalf("writeMihomoConfig returned error: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("nodes were dropped from the core config: %+v", skipped)
	}

	// Имена из карты обязаны совпасть с тем, что реально записано в конфиг.
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read generated config: %v", err)
	}
	var doc struct {
		Proxies     []map[string]any `yaml:"proxies"`
		ProxyGroups []map[string]any `yaml:"proxy-groups"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("generated config does not parse: %v", err)
	}

	declared := map[string]bool{}
	for _, p := range doc.Proxies {
		name, _ := p["name"].(string)
		declared[name] = true
	}

	for _, n := range nodes {
		coreName, ok := names[n.ID]
		if !ok {
			t.Errorf("node %s:%d has no core name in the returned map", n.Server, n.Port)
			continue
		}
		if !declared[coreName] {
			t.Errorf("core name %q for %s:%d is not declared in the config", coreName, n.Server, n.Port)
		}
		if probeName := coreNameFor(names, n); probeName != coreName {
			t.Errorf("probe would select %q while the config declares %q", probeName, coreName)
		}
	}

	// Главное: у дублей имена РАЗНЫЕ, иначе PUT уводит пробу на чужой узел.
	distinct := map[string]bool{}
	for _, n := range nodes {
		distinct[coreNameFor(names, n)] = true
	}
	if len(distinct) != len(nodes) {
		t.Errorf("duplicate names collapsed to %d core names for %d nodes: %v", len(distinct), len(nodes), distinct)
	}
}

// TestWriteMihomoConfigSelectsOwnNode — регресс на исходный сценарий: проба
// для второго дубля не должна слать имя первого.
func TestWriteMihomoConfigSelectsOwnNode(t *testing.T) {
	nodes := duplicateNameNodes()
	path := filepath.Join(t.TempDir(), "config.yaml")
	names, skipped, err := writeMihomoConfig(path, nodes, Defaults())
	if err != nil {
		t.Fatalf("writeMihomoConfig returned error: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("nodes were dropped from the core config: %+v", skipped)
	}
	first := coreNameFor(names, nodes[0])
	second := coreNameFor(names, nodes[1])
	if first == second {
		t.Fatalf("both duplicates are probed under %q: the second verdict belongs to the first server", first)
	}
	if first != "🇳🇱" {
		t.Errorf("first occurrence was renamed to %q — config should stay readable", first)
	}
}
