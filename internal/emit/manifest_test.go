package emit

import (
	"encoding/json"
	"testing"

	"github.com/kyomufs/proxprobe/internal/model"
)

type manifestShape struct {
	Generated string `json:"generated"`
	Nodes     []struct {
		Name    string   `json:"name"`
		Proto   string   `json:"proto"`
		Server  string   `json:"server"`
		Port    int      `json:"port"`
		Sources []string `json:"sources"`
	} `json:"nodes"`
}

func parseManifest(t *testing.T, body []byte) manifestShape {
	t.Helper()
	var doc manifestShape
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("manifest does not parse: %v", err)
	}
	return doc
}

// Манифест обязан называть узлы теми же именами, что ядро: панель ищет узел
// по имени из группы, и разошедшееся имя — это узел без подписки.
func TestManifestNamesMatchTheProfile(t *testing.T) {
	nodes := []model.Node{
		sampleNode("NL 1", "first.example.com"),
		sampleNode("NL 1", "second.example.com"),
	}
	body, err := RenderManifest(nodes)
	if err != nil {
		t.Fatalf("RenderManifest returned error: %v", err)
	}
	doc := parseManifest(t, body)
	if len(doc.Nodes) != 2 {
		t.Fatalf("manifest has %d nodes, want 2", len(doc.Nodes))
	}

	core, err := Mihomo(nodes)
	if err != nil {
		t.Fatalf("Mihomo returned error: %v", err)
	}
	profile := parseMihomo(t, core)
	if len(profile.Proxies) != len(doc.Nodes) {
		t.Fatalf("profile has %d proxies, manifest %d nodes", len(profile.Proxies), len(doc.Nodes))
	}
	for i, want := range profile.Proxies {
		if doc.Nodes[i].Name != want.Name {
			t.Errorf("node %d: manifest name %q, profile name %q", i, doc.Nodes[i].Name, want.Name)
		}
	}

	// Повтор названия в подписке — норма; без уникализации манифест не смог
	// бы отличить два узла друг от друга.
	if doc.Nodes[0].Name == doc.Nodes[1].Name {
		t.Errorf("both nodes are named %q, want unique names", doc.Nodes[0].Name)
	}
}

// Подписка узла — единственный способ показать его в нужной группе: в
// профиле ядра её нет.
func TestManifestCarriesTheSourceOfEveryNode(t *testing.T) {
	n := sampleNode("NL 1", "first.example.com")
	n.Source = []string{"myprotechnology", "backup"}

	body, err := RenderManifest([]model.Node{n})
	if err != nil {
		t.Fatalf("RenderManifest returned error: %v", err)
	}
	doc := parseManifest(t, body)
	if len(doc.Nodes) != 1 {
		t.Fatalf("manifest has %d nodes, want 1", len(doc.Nodes))
	}
	got := doc.Nodes[0]
	if len(got.Sources) != 2 || got.Sources[0] != "myprotechnology" || got.Sources[1] != "backup" {
		t.Errorf("sources = %v, want both subscriptions", got.Sources)
	}
	if got.Server != "first.example.com" || got.Port != 443 || got.Proto != string(model.ProtoVLESS) {
		t.Errorf("node = %+v, want the address and protocol of the profile entry", got)
	}
	if doc.Generated == "" {
		t.Error("generated timestamp is empty")
	}
}
