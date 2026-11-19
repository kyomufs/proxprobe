package emit

import (
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/kyomufs/proxprobe/internal/model"
)

// mihomoProfile — то, что должно оказаться в файле ядра.
type mihomoProfile struct {
	MixedPort          int    `yaml:"mixed-port"`
	BindAddress        string `yaml:"bind-address"`
	ExternalController string `yaml:"external-controller"`
	Mode               string `yaml:"mode"`
	Proxies            []struct {
		Name string `yaml:"name"`
	} `yaml:"proxies"`
	Groups []struct {
		Name    string   `yaml:"name"`
		Type    string   `yaml:"type"`
		Proxies []string `yaml:"proxies"`
	} `yaml:"proxy-groups"`
	Rules []string `yaml:"rules"`
}

func parseMihomo(t *testing.T, body []byte) mihomoProfile {
	t.Helper()
	var doc mihomoProfile
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("generated core profile does not parse: %v", err)
	}
	return doc
}

func TestMihomoPinsAddressesTheGatewayExpects(t *testing.T) {
	body, err := Mihomo([]model.Node{sampleNode("NL 1", "first.example.com")})
	if err != nil {
		t.Fatalf("Mihomo returned error: %v", err)
	}
	doc := parseMihomo(t, body)

	// Порт и контроллер — часть контракта с шлюзом: он стучится на 7891 и
	// переключает группу через 9091. Ядро без этих полей поднялось бы на
	// своих умолчаниях, и связь разошлась бы молча.
	if doc.MixedPort != MihomoPort {
		t.Errorf("mixed-port = %d, want %d", doc.MixedPort, MihomoPort)
	}
	if doc.ExternalController != MihomoController {
		t.Errorf("external-controller = %q, want %q", doc.ExternalController, MihomoController)
	}
	if doc.BindAddress != "127.0.0.1" {
		t.Errorf("bind-address = %q, want loopback only", doc.BindAddress)
	}
	if doc.Mode != "rule" {
		t.Errorf("mode = %q, want rule", doc.Mode)
	}
	if len(doc.Rules) != 1 || doc.Rules[0] != "MATCH,"+MihomoGroup {
		t.Errorf("rules = %v, want one MATCH,%s", doc.Rules, MihomoGroup)
	}
}

func TestMihomoGroupStartsWithDirect(t *testing.T) {
	body, err := Mihomo([]model.Node{
		sampleNode("NL 1", "first.example.com"),
		sampleNode("DE 1", "second.example.com"),
	})
	if err != nil {
		t.Fatalf("Mihomo returned error: %v", err)
	}
	doc := parseMihomo(t, body)

	if len(doc.Groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(doc.Groups))
	}
	group := doc.Groups[0]
	if group.Name != MihomoGroup || group.Type != "select" {
		t.Errorf("group = %q/%q, want %q/select", group.Name, group.Type, MihomoGroup)
	}
	// DIRECT первым: пока хост-маршрут жив, повтор через ноду не нужен, а
	// порядок здесь — порядок выбора при первом запуске.
	want := []string{"DIRECT", "NL 1", "DE 1"}
	if len(group.Proxies) != len(want) {
		t.Fatalf("group = %v, want %v", group.Proxies, want)
	}
	for i := range want {
		if group.Proxies[i] != want[i] {
			t.Fatalf("group = %v, want %v", group.Proxies, want)
		}
	}
}

func TestMihomoHasNoURLTestGroup(t *testing.T) {
	body, err := Mihomo([]model.Node{sampleNode("NL 1", "first.example.com")})
	if err != nil {
		t.Fatalf("Mihomo returned error: %v", err)
	}
	for _, group := range parseMihomo(t, body).Groups {
		// url-test сам переключает узел по задержке и спорил бы с тем, кто
		// переключает по отказу: повтор уехал бы обратно в середине.
		if group.Type == "url-test" {
			t.Fatalf("group %q is url-test; the exit is switched by the gateway", group.Name)
		}
	}
}

func TestMihomoRenamesNodeCalledLikeTheGroup(t *testing.T) {
	nodes := []model.Node{
		sampleNode(MihomoGroup, "first.example.com"),
		sampleNode("DIRECT", "second.example.com"),
	}
	body, err := Mihomo(nodes)
	if err != nil {
		t.Fatalf("Mihomo returned error: %v", err)
	}
	doc := parseMihomo(t, body)

	if len(doc.Proxies) != 2 {
		t.Fatalf("got %d proxies, want 2", len(doc.Proxies))
	}
	for _, p := range doc.Proxies {
		// Узел с именем группы делает конфиг циклом, узел с именем DIRECT
		// отменяет прямой выход — оба имени уже заняты профилем.
		if p.Name == MihomoGroup || p.Name == "DIRECT" {
			t.Fatalf("proxy %q took a name the profile needs", p.Name)
		}
	}
}

func TestMihomoWithoutNodesKeepsTheGroupUsable(t *testing.T) {
	body, err := Mihomo(nil)
	if err != nil {
		t.Fatalf("Mihomo returned error: %v", err)
	}
	doc := parseMihomo(t, body)
	if len(doc.Proxies) != 0 {
		t.Fatalf("got %d proxies, want none", len(doc.Proxies))
	}
	if len(doc.Groups) != 1 || len(doc.Groups[0].Proxies) != 1 || doc.Groups[0].Proxies[0] != "DIRECT" {
		t.Fatalf("group = %+v, want a single DIRECT member", doc.Groups)
	}
}
