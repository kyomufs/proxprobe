package parse

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kyomufs/proxprobe/internal/detect"
	"github.com/kyomufs/proxprobe/internal/model"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatalf("cannot read fixture %s: %v", name, err)
	}
	return body
}

// TestFixtureFormatsDetection держит связку "фикстура → формат" под тестом:
// если детектор начнёт путать форматы, это видно здесь, а не в проде.
func TestFixtureFormatsDetection(t *testing.T) {
	tests := []struct {
		fixture string
		want    detect.Format
	}{
		{"goida-links.txt", detect.FormatLinks},
		{"pro1link-clash.yaml", detect.FormatClash},
		{"sunmiao-clash.yaml", detect.FormatClash},
		{"pro1link-xray-bundles.json", detect.FormatXrayBundles},
		{"proxypool-singbox.json", detect.FormatSingbox},
	}
	for _, tt := range tests {
		got, _ := detect.Sniff(readFixture(t, tt.fixture))
		if got != tt.want {
			t.Errorf("%s detected as %q, want %q", tt.fixture, got, tt.want)
		}
	}
}

func TestParseLinksFixture(t *testing.T) {
	res := Links(readFixture(t, "goida-links.txt"), "goida")

	// В урезанной фикстуре по 4 ссылки на протокол плюс одна tuic.
	if len(res.Skips) != 0 {
		t.Errorf("parser skipped %d lines it should have handled: %+v", len(res.Skips), res.Skips)
	}
	counts := map[string]int{}
	for _, n := range res.Nodes {
		counts[n.Proto]++
	}
	want := map[string]int{
		model.ProtoVLESS: 4, model.ProtoVMess: 4, model.ProtoTrojan: 4,
		model.ProtoSS: 4, model.ProtoSocks5: 4, model.ProtoHysteria2: 4,
		model.ProtoTuic: 1,
	}
	for proto, n := range want {
		if counts[proto] != n {
			t.Errorf("%s: parsed %d nodes, want %d", proto, counts[proto], n)
		}
	}
}

func TestParseLinksKeepsRealityFields(t *testing.T) {
	res := Links(readFixture(t, "goida-links.txt"), "goida")

	var found bool
	for _, n := range res.Nodes {
		if n.Proto != model.ProtoVLESS || n.Security != model.SecReality {
			continue
		}
		found = true
		if n.PublicKey == "" {
			t.Errorf("reality node %q has no public key", n.Name)
		}
		if n.ShortID == "" {
			t.Errorf("reality node %q has no short id", n.Name)
		}
		if n.SNI == "" {
			t.Errorf("reality node %q has no sni", n.Name)
		}
	}
	if !found {
		t.Fatal("fixture contains no reality vless node — test proves nothing")
	}
}

func TestParseLinksKeepsShareLinkInRaw(t *testing.T) {
	res := Links(readFixture(t, "goida-links.txt"), "goida")
	for _, n := range res.Nodes {
		link, ok := n.Raw["link"].(string)
		if !ok || link == "" {
			t.Fatalf("node %q lost its original share link", n.Name)
		}
	}
}

func TestParseClashRealityFixture(t *testing.T) {
	res := Clash(readFixture(t, "pro1link-clash.yaml"), "pro1link-clash")

	if len(res.Nodes) == 0 {
		t.Fatalf("no nodes parsed, skips: %+v", res.Skips)
	}
	for _, n := range res.Nodes {
		if n.Proto != model.ProtoVLESS {
			t.Errorf("node %q has proto %q, want vless", n.Name, n.Proto)
		}
		if n.Security != model.SecReality {
			t.Errorf("node %q has security %q, want reality", n.Name, n.Security)
		}
		if n.PublicKey == "" {
			t.Errorf("node %q lost reality public key (reality-opts.public-key)", n.Name)
		}
		if n.SNI == "" {
			t.Errorf("node %q lost servername", n.Name)
		}
	}
}

func TestParseClashMixedFixture(t *testing.T) {
	res := Clash(readFixture(t, "sunmiao-clash.yaml"), "sunmiao")

	types := map[string]int{}
	for _, n := range res.Nodes {
		types[n.Proto]++
	}
	for _, want := range []string{model.ProtoVLESS, model.ProtoVMess, model.ProtoTrojan} {
		if types[want] == 0 {
			t.Errorf("fixture contains %s nodes but parser produced none", want)
		}
	}
	if len(res.Skips) != 0 {
		t.Errorf("unexpected skips: %+v", res.Skips)
	}
}

func TestParseClashKeepsWSOpts(t *testing.T) {
	res := Clash(readFixture(t, "sunmiao-clash.yaml"), "sunmiao")

	var checked bool
	for _, n := range res.Nodes {
		if n.Network != model.NetWS {
			continue
		}
		checked = true
		if n.Path == "" {
			t.Errorf("ws node %q lost path from ws-opts", n.Name)
		}
		if n.Host == "" {
			t.Errorf("ws node %q lost Host header from ws-opts", n.Name)
		}
	}
	if !checked {
		t.Fatal("fixture contains no ws node — test proves nothing")
	}
}

func TestParseXrayBundles(t *testing.T) {
	res := XrayBundles(readFixture(t, "pro1link-xray-bundles.json"), "pro1link-xray")

	if len(res.Nodes) == 0 {
		t.Fatalf("no nodes parsed, skips: %+v", res.Skips)
	}
	for _, n := range res.Nodes {
		switch n.Proto {
		case "freedom", "blackhole", "dns", "loopback", "":
			t.Errorf("service outbound leaked into nodes as %q (bundle %q)", n.Proto, n.Name)
		}
		if n.Server == "" || n.Port == 0 {
			t.Errorf("node %q has no endpoint", n.Name)
		}
	}
}

func TestParseXrayBundlesKeepsReality(t *testing.T) {
	res := XrayBundles(readFixture(t, "pro1link-xray-bundles.json"), "pro1link-xray")

	var checked bool
	for _, n := range res.Nodes {
		if n.Security != model.SecReality {
			continue
		}
		checked = true
		if n.PublicKey == "" {
			t.Errorf("reality node %q lost publicKey from realitySettings", n.Name)
		}
		if n.ShortID == "" {
			t.Errorf("reality node %q lost shortId from realitySettings", n.Name)
		}
		if n.SNI == "" {
			t.Errorf("reality node %q lost serverName from realitySettings", n.Name)
		}
	}
	if !checked {
		t.Fatal("fixture contains no reality node — test proves nothing")
	}
}

func TestParseSingboxSkipsGroups(t *testing.T) {
	res := Singbox(readFixture(t, "proxypool-singbox.json"), "proxypool")

	if len(res.Nodes) == 0 {
		t.Fatalf("no nodes parsed, skips: %+v", res.Skips)
	}
	for _, n := range res.Nodes {
		switch n.Proto {
		case "selector", "urltest", "direct", "block", "dns", "":
			t.Errorf("group outbound leaked into nodes as %q", n.Proto)
		}
	}
}

func TestParseSingboxNodeFields(t *testing.T) {
	res := Singbox(readFixture(t, "proxypool-singbox.json"), "proxypool")

	protos := map[string]bool{}
	for _, n := range res.Nodes {
		protos[n.Proto] = true
		if n.Name == "" {
			t.Errorf("node %s:%d lost its tag", n.Server, n.Port)
		}
		if n.Credential() == "" {
			t.Errorf("node %q (%s) has no credentials", n.Name, n.Proto)
		}
	}
	// Набор проверяемых протоколов взят из фикстуры: в ней есть vless,
	// vmess и hysteria2. trojan и shadowsocks в полном источнике есть, но
	// в урезанную фикстуру не попали.
	for _, want := range []string{model.ProtoVLESS, model.ProtoVMess, model.ProtoHysteria2} {
		if !protos[want] {
			t.Errorf("fixture contains %s outbounds but parser produced none", want)
		}
	}
}

func TestParseSingboxReality(t *testing.T) {
	res := Singbox(readFixture(t, "proxypool-singbox.json"), "proxypool")
	for _, n := range res.Nodes {
		if n.Proto != model.ProtoVLESS || n.Security != model.SecReality {
			continue
		}
		if n.PublicKey == "" {
			t.Errorf("reality node %q lost tls.reality.public_key", n.Name)
		}
	}
}

// TestParseLinkHandlesHTMLEscapedAmpersand закрывает реальный случай из
// источника goida-vpn-configs: разделитель параметров приходит как &amp;,
// и без снятия экранирования pbk склеивается с соседним параметром
// ("X&amp;fp=qq"), после чего узел отбраковывается как "reality without pbk".
func TestParseLinkHandlesHTMLEscapedAmpersand(t *testing.T) {
	line := "vless://a5eddeef-737a-4126-8d1e-527f85d7ed18@2.26.129.247:443" +
		"?security=reality&amp;encryption=none&amp;pbk=gPTBA-gVUWAK9yziB_v_sGSncm0LwBQvEAsTQZK4jEE" +
		"&amp;fp=qq&amp;type=tcp&amp;sni=example.com#node"

	node, err := ParseLink(line)
	if err != nil {
		t.Fatalf("ParseLink rejected an HTML-escaped link: %v", err)
	}
	if node.PublicKey != "gPTBA-gVUWAK9yziB_v_sGSncm0LwBQvEAsTQZK4jEE" {
		t.Errorf("pbk = %q, want the value before &amp;fp", node.PublicKey)
	}
	if node.Fingerprint != "qq" {
		t.Errorf("fp = %q, want qq: parameters after &amp; were glued together", node.Fingerprint)
	}
	if node.SNI != "example.com" {
		t.Errorf("sni = %q, want example.com", node.SNI)
	}
}

// TestParseVMessBoolTLS закрывает реальный случай: источник пишет tls
// булевым false, а не строкой. С жёстким типом поля json.Unmarshal падает
// на всём теле, и узел теряется целиком.
func TestParseVMessBoolTLS(t *testing.T) {
	// {"v":2,"ps":"x","add":"1.2.3.4","port":443,"id":"u","aid":0,"net":"ws","tls":false}
	payload := "eyJ2IjoyLCJwcyI6IngiLCJhZGQiOiIxLjIuMy40IiwicG9ydCI6NDQzLCJpZCI6InUiLCJhaWQiOjAsIm5ldCI6IndzIiwidGxzIjpmYWxzZX0="
	node, err := ParseLink("vmess://" + payload)
	if err != nil {
		t.Fatalf("ParseLink rejected vmess with boolean tls: %v", err)
	}
	if node.Server != "1.2.3.4" || node.Port != 443 {
		t.Errorf("endpoint = %s:%d, want 1.2.3.4:443", node.Server, node.Port)
	}
	if node.Security == model.SecTLS {
		t.Error("tls=false was read as enabled")
	}
}
