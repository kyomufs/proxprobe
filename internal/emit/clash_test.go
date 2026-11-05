package emit

import (
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/kyomufs/proxprobe/internal/model"
)

func sampleNode(name, server string) model.Node {
	n := model.Node{
		Proto: model.ProtoVLESS, Name: name, Server: server, Port: 443,
		UUID: "b9e20aa5-2065-447b-9c9e-0ec9fe93a687", Network: model.NetTCP,
		Security: model.SecReality, SNI: "tyctyvsjec.localto.net",
		PublicKey: "tei5wyEWqA4cWDUe-gRJkAiOYiA7FQAZ30p6sap", ShortID: "35a485128f35f588",
		Fingerprint: "qq", Flow: "xtls-rprx-vision",
	}
	n.Finalize()
	return n
}

type parsedDoc struct {
	Proxies []map[string]any `yaml:"proxies"`
	Groups  []struct {
		Name    string   `yaml:"name"`
		Type    string   `yaml:"type"`
		Proxies []string `yaml:"proxies"`
		URL     string   `yaml:"url"`
	} `yaml:"proxy-groups"`
	Rules []string `yaml:"rules"`
}

func parseDoc(t *testing.T, body []byte) parsedDoc {
	t.Helper()
	var doc parsedDoc
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("generated YAML does not parse: %v", err)
	}
	return doc
}

func TestSubscriptionBuildsProxyAndAutoGroups(t *testing.T) {
	body, err := Subscription([]model.Node{
		sampleNode("NL 1", "first.example.com"),
		sampleNode("NL 2", "second.example.com"),
	})
	if err != nil {
		t.Fatalf("Subscription returned error: %v", err)
	}
	doc := parseDoc(t, body)

	if len(doc.Proxies) != 2 {
		t.Fatalf("generated %d proxies, want 2", len(doc.Proxies))
	}
	if len(doc.Groups) != 2 {
		t.Fatalf("generated %d groups, want PROXY and AUTO", len(doc.Groups))
	}

	proxy, auto := doc.Groups[0], doc.Groups[1]
	if proxy.Name != ProxyGroupName || proxy.Type != "select" {
		t.Errorf("first group = %s/%s, want PROXY/select", proxy.Name, proxy.Type)
	}
	if len(proxy.Proxies) != 3 || proxy.Proxies[0] != AutoGroupName {
		t.Errorf("PROXY members = %v, want AUTO and both nodes", proxy.Proxies)
	}
	if auto.Name != AutoGroupName || auto.Type != "url-test" {
		t.Errorf("second group = %s/%s, want AUTO/url-test", auto.Name, auto.Type)
	}
	if auto.URL != testURL {
		t.Errorf("AUTO url = %q, want %q", auto.URL, testURL)
	}
	if len(doc.Rules) != 1 || doc.Rules[0] != "MATCH,PROXY" {
		t.Errorf("rules = %v, want MATCH,PROXY", doc.Rules)
	}
}

func TestSubscriptionKeepsRealityFields(t *testing.T) {
	body, err := Subscription([]model.Node{sampleNode("NL 1", "first.example.com")})
	if err != nil {
		t.Fatalf("Subscription returned error: %v", err)
	}
	doc := parseDoc(t, body)

	p := doc.Proxies[0]
	if p["uuid"] != "b9e20aa5-2065-447b-9c9e-0ec9fe93a687" {
		t.Errorf("uuid lost: %v", p["uuid"])
	}
	reality, ok := p["reality-opts"].(map[string]any)
	if !ok {
		t.Fatalf("reality-opts lost: %v", p["reality-opts"])
	}
	if reality["public-key"] != "tei5wyEWqA4cWDUe-gRJkAiOYiA7FQAZ30p6sap" {
		t.Errorf("public key lost: %v", reality["public-key"])
	}
	if p["flow"] != "xtls-rprx-vision" {
		t.Errorf("flow lost: %v", p["flow"])
	}
}

func TestSubscriptionUniqueNamesAndReservedGroups(t *testing.T) {
	body, err := Subscription([]model.Node{
		sampleNode("PROXY", "first.example.com"),
		sampleNode("PROXY", "second.example.com"),
	})
	if err != nil {
		t.Fatalf("Subscription returned error: %v", err)
	}
	doc := parseDoc(t, body)

	names := map[string]bool{}
	for _, p := range doc.Proxies {
		name, _ := p["name"].(string)
		if names[name] {
			t.Fatalf("duplicate proxy name %q", name)
		}
		names[name] = true
	}
	if names[ProxyGroupName] {
		t.Fatalf("a proxy is named %q: mihomo sees a loop in ProxyGroup", ProxyGroupName)
	}
}

func TestSubscriptionWithoutNodesIsValid(t *testing.T) {
	body, err := Subscription(nil)
	if err != nil {
		t.Fatalf("Subscription returned error: %v", err)
	}
	doc := parseDoc(t, body)
	if len(doc.Proxies) != 0 {
		t.Fatalf("empty input generated %d proxies", len(doc.Proxies))
	}
	if len(doc.Groups) != 1 || doc.Groups[0].Proxies[0] != "DIRECT" {
		t.Fatalf("empty profile must stay importable: %+v", doc.Groups)
	}
}
