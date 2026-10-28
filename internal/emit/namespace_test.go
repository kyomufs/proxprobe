package emit

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/kyomufs/proxprobe/internal/model"
)

// clashDocForTest — то, что нужно от готового профиля в тестах группы имён.
type clashDocForTest struct {
	Proxies     []map[string]any `yaml:"proxies"`
	ProxyGroups []map[string]any `yaml:"proxy-groups"`
}

func parseClashDoc(t *testing.T, body []byte) clashDocForTest {
	t.Helper()
	var doc clashDocForTest
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("generated YAML does not parse: %v", err)
	}
	return doc
}

func groupNames(doc clashDocForTest) map[string]bool {
	out := map[string]bool{}
	for _, g := range doc.ProxyGroups {
		if name, ok := g["name"].(string); ok {
			out[name] = true
		}
	}
	return out
}

// vlessNode собирает узел с заданным именем и адресом: разные адреса дают
// разные ID, то есть дубли имён не схлопываются дедупом.
func vlessNode(name, server string) model.Node {
	n := model.Node{
		Proto: model.ProtoVLESS, Name: name, Server: server, Port: 443,
		UUID: "11111111-2222-3333-4444-555555555555",
	}
	n.Finalize()
	return n
}

// TestClashNodeNameNeverEqualsGroupName закрывает реальный случай: в подписке
// узел назван «PROXY», «AUTO» или так, что countryOf делает из имени группу
// («Другое», «Авто»). Пространство имён у mihomo общее, и такой конфиг
// отвергается целиком: "loop is detected in ProxyGroup".
func TestClashNodeNameNeverEqualsGroupName(t *testing.T) {
	nodes := []model.Node{
		vlessNode("PROXY", "one.example.com"),
		vlessNode("AUTO", "two.example.com"),
		// Два узла одной страны: countryOf даст «Авто», и группа появится.
		vlessNode("Авто", "three.example.com"),
		vlessNode("Авто второй", "four.example.com"),
	}

	body, err := Clash(nodes)
	if err != nil {
		t.Fatalf("Clash() returned error: %v", err)
	}
	doc := parseClashDoc(t, body)
	groups := groupNames(doc)

	if len(doc.Proxies) != len(nodes) {
		t.Fatalf("generated %d proxies, want %d", len(doc.Proxies), len(nodes))
	}

	seen := map[string]bool{}
	for _, p := range doc.Proxies {
		name, _ := p["name"].(string)
		if name == "" {
			t.Fatalf("proxy without a name: %v", p)
		}
		if groups[name] {
			t.Errorf("proxy %q shares its name with a group: mihomo rejects the whole profile", name)
		}
		if seen[name] {
			t.Errorf("duplicate proxy name %q survived", name)
		}
		seen[name] = true
	}
}

// TestClashReservesCountryGroupNames проверяет именно вычисление имён групп
// заранее: страна появляется только при двух узлах, и узел с её именем должен
// получить суффикс даже если сам он не в этой стране.
func TestClashReservesCountryGroupNames(t *testing.T) {
	nodes := []model.Node{
		vlessNode("Нидерланды быстрый", "nl1.example.com"),
		vlessNode("Нидерланды медленный", "nl2.example.com"),
		vlessNode("Нидерланды", "standalone.example.com"),
	}

	body, err := Clash(nodes)
	if err != nil {
		t.Fatalf("Clash() returned error: %v", err)
	}
	doc := parseClashDoc(t, body)
	groups := groupNames(doc)

	if !groups["Нидерланды"] {
		t.Fatalf("country group was not created, test proves nothing: %v", groups)
	}
	for _, p := range doc.Proxies {
		if name, _ := p["name"].(string); name == "Нидерланды" {
			t.Errorf("node kept the group name: %v", doc.Proxies)
		}
	}
}

// TestClashKeepsNamesReadable — обратная сторона: уникализация не должна
// переименовывать узлы, которым ничего не мешает. Первое вхождение имени
// остаётся как есть.
func TestClashKeepsNamesReadable(t *testing.T) {
	nodes := []model.Node{
		vlessNode("🇳🇱 Нидерланды TURBO #4", "a.example.com"),
	}
	body, err := Clash(nodes)
	if err != nil {
		t.Fatalf("Clash() returned error: %v", err)
	}
	doc := parseClashDoc(t, body)
	name, _ := doc.Proxies[0]["name"].(string)
	if name != "🇳🇱 Нидерланды TURBO #4" {
		t.Errorf("unobstructed name was rewritten: %q", name)
	}
	if strings.Contains(name, " #2") {
		t.Errorf("first occurrence got a suffix: %q", name)
	}
}
