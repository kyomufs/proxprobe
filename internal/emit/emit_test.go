package emit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/kyomufs/proxprobe/internal/model"
)

func sampleNodes(t *testing.T) []model.Node {
	t.Helper()

	reality := model.Node{
		Proto: model.ProtoVLESS, Name: "NL TURBO 1", Server: "tyctyvsjec.localto.net", Port: 443,
		UUID: "b9e20aa5-2065-447b-9c9e-0ec9fe93a687", Network: model.NetTCP,
		Security: model.SecReality, SNI: "tyctyvsjec.localto.net",
		PublicKey: "tei5wyEWqA4cWDUe-gRJkAiOYiA7FQAZ30p6sap", ShortID: "35a485128f35f588",
		Fingerprint: "qq", Flow: "xtls-rprx-vision",
	}
	reality.Finalize()

	ws := model.Node{
		Proto: model.ProtoVLESS, Name: "SG SGP 4", Server: "104.18.35.86", Port: 8080,
		UUID: "e5cc16a6-ea42-46b2-82ae-ad2157e1641b", Network: model.NetWS,
		Path: "/sg-melbi", Host: "hhlfy.twiladaphne.ndjp.net", Security: model.SecNone,
	}
	ws.Finalize()

	return []model.Node{reality, ws}
}

func TestClashRoundTripKeepsRealityFields(t *testing.T) {
	body, err := Clash(sampleNodes(t))
	if err != nil {
		t.Fatalf("Clash() returned error: %v", err)
	}

	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("generated YAML does not parse: %v", err)
	}
	if len(doc.Proxies) != 2 {
		t.Fatalf("generated %d proxies, want 2", len(doc.Proxies))
	}

	var found bool
	for _, p := range doc.Proxies {
		if p["name"] != "NL TURBO 1" {
			continue
		}
		found = true
		if p["uuid"] != "b9e20aa5-2065-447b-9c9e-0ec9fe93a687" {
			t.Errorf("uuid lost: %v", p["uuid"])
		}
		reality, ok := p["reality-opts"].(map[string]any)
		if !ok {
			t.Fatalf("reality-opts lost entirely: %v", p)
		}
		if reality["public-key"] != "tei5wyEWqA4cWDUe-gRJkAiOYiA7FQAZ30p6sap" {
			t.Errorf("public key lost: %v", reality["public-key"])
		}
		if reality["short-id"] != "35a485128f35f588" {
			t.Errorf("short id lost: %v", reality["short-id"])
		}
		if p["flow"] != "xtls-rprx-vision" {
			t.Errorf("flow lost: %v", p["flow"])
		}
	}
	if !found {
		t.Fatal("reality node not present in generated Clash config")
	}
}

func TestClashKeepsWSOpts(t *testing.T) {
	body, err := Clash(sampleNodes(t))
	if err != nil {
		t.Fatalf("Clash() returned error: %v", err)
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("generated YAML does not parse: %v", err)
	}

	for _, p := range doc.Proxies {
		if p["name"] != "SG SGP 4" {
			continue
		}
		ws, ok := p["ws-opts"].(map[string]any)
		if !ok {
			t.Fatalf("ws-opts lost: %v", p)
		}
		if ws["path"] != "/sg-melbi" {
			t.Errorf("path lost: %v", ws["path"])
		}
		headers, ok := ws["headers"].(map[string]any)
		if !ok {
			t.Fatalf("ws headers lost: %v", ws)
		}
		if headers["Host"] != "hhlfy.twiladaphne.ndjp.net" {
			t.Errorf("Host header lost: %v", headers["Host"])
		}
		return
	}
	t.Fatal("ws node not present in generated Clash config")
}

func TestClashUsesRawWhenPresent(t *testing.T) {
	n := sampleNodes(t)[0]
	n.Raw = map[string]any{"clash": map[string]any{
		"type": "vless", "server": n.Server, "port": n.Port,
		"packet-encoding": "xudp", "udp": true,
	}}
	body, err := Clash([]model.Node{n})
	if err != nil {
		t.Fatalf("Clash() returned error: %v", err)
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("generated YAML does not parse: %v", err)
	}
	if doc.Proxies[0]["packet-encoding"] != "xudp" {
		t.Errorf("raw clash representation was not reused: %v", doc.Proxies[0])
	}
}

func TestBestFiltersDeadNodes(t *testing.T) {
	nodes := sampleNodes(t)
	nodes[0].Raw = map[string]any{"delay_ms": 120.0}
	nodes[1].Raw = map[string]any{"delay_ms": 0.0} // не прошёл проверку

	body, err := Best(nodes)
	if err != nil {
		t.Fatalf("Best() returned error: %v", err)
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("generated YAML does not parse: %v", err)
	}
	if len(doc.Proxies) != 1 {
		t.Fatalf("best profile has %d proxies, want only the live one", len(doc.Proxies))
	}
	if doc.Proxies[0]["name"] != "NL TURBO 1" {
		t.Errorf("wrong node kept: %v", doc.Proxies[0]["name"])
	}
}

func TestBestSortsByDelay(t *testing.T) {
	nodes := sampleNodes(t)
	nodes[0].Raw = map[string]any{"delay_ms": 400.0}
	nodes[1].Raw = map[string]any{"delay_ms": 90.0}

	body, err := Best(nodes)
	if err != nil {
		t.Fatalf("Best() returned error: %v", err)
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("generated YAML does not parse: %v", err)
	}
	if doc.Proxies[0]["name"] != "SG SGP 4" {
		t.Errorf("fastest node is not first: %v", doc.Proxies[0]["name"])
	}
}

func TestWriteAllCreatesFiles(t *testing.T) {
	dir := t.TempDir()
	paths, err := WriteAll(dir, sampleNodes(t), []string{"clash", "best"})
	if err != nil {
		t.Fatalf("WriteAll() returned error: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("wrote %d files, want 2", len(paths))
	}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			t.Errorf("file %s not written: %v", p, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("file %s is empty", p)
		}
		if !strings.HasPrefix(filepath.Base(p), filepath.Base(p)) {
			t.Errorf("unexpected path %s", p)
		}
	}
}

func TestClashUniqueNames(t *testing.T) {
	// Два РАЗНЫХ сервера с одинаковым именем: дедуп по ID их не схлопывает,
	// но mihomo отвергает конфиг с повторяющимся именем целиком.
	a := sampleNodes(t)[0]
	a.Name = "🇺🇸"
	a.Server = "one.example.com"
	a.Finalize()
	b := sampleNodes(t)[0]
	b.Name = "🇺🇸"
	b.Server = "two.example.com"
	b.Finalize()

	if a.ID == b.ID {
		t.Fatal("test setup is wrong: nodes must be different")
	}

	body, err := Clash([]model.Node{a, b})
	if err != nil {
		t.Fatalf("Clash() returned error: %v", err)
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("generated YAML does not parse: %v", err)
	}
	if len(doc.Proxies) != 2 {
		t.Fatalf("got %d proxies, want 2", len(doc.Proxies))
	}
	if doc.Proxies[0]["name"] == doc.Proxies[1]["name"] {
		t.Fatalf("duplicate names survived: %v and %v", doc.Proxies[0]["name"], doc.Proxies[1]["name"])
	}
}
