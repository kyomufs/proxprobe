package probe

import (
	"testing"

	"github.com/kyomufs/proxprobe/internal/model"
)

func TestNormaliseCipher(t *testing.T) {
	// sing-box называет шифр chacha20-poly1305, mihomo — chacha20-ietf-poly1305.
	// Без приведения ядро падает целым конфигом на "unknown method".
	if got := NormaliseCipher("chacha20-poly1305"); got != "chacha20-ietf-poly1305" {
		t.Errorf("NormaliseCipher(chacha20-poly1305) = %q, want chacha20-ietf-poly1305", got)
	}
	if got := NormaliseCipher("aes-256-gcm"); got != "aes-256-gcm" {
		t.Errorf("known cipher was rewritten: %q", got)
	}
}

func TestCoreCompatibleRejects(t *testing.T) {
	tests := []struct {
		name string
		node model.Node
		ok   bool
	}{
		{
			name: "anytls is not supported by mihomo config",
			node: model.Node{Proto: model.ProtoAnyTLS, Server: "a.com", Port: 443, Password: "p"},
			ok:   false,
		},
		{
			name: "vless without uuid",
			node: model.Node{Proto: model.ProtoVLESS, Server: "a.com", Port: 443},
			ok:   false,
		},
		{
			name: "ss without cipher",
			node: model.Node{Proto: model.ProtoSS, Server: "a.com", Port: 443, Password: "p"},
			ok:   false,
		},
		{
			name: "reality without public key",
			node: model.Node{Proto: model.ProtoVLESS, Server: "a.com", Port: 443, UUID: "u", Security: model.SecReality},
			ok:   false,
		},
		{
			name: "healthy vless",
			node: model.Node{Proto: model.ProtoVLESS, Server: "a.com", Port: 443, UUID: "u"},
			ok:   true,
		},
		{
			name: "no endpoint",
			node: model.Node{Proto: model.ProtoVLESS, Server: "", Port: 0, UUID: "u"},
			ok:   false,
		},
	}
	for _, tt := range tests {
		got, reason := CoreCompatible(tt.node)
		if got != tt.ok {
			t.Errorf("%s: CoreCompatible = %v (%s), want %v", tt.name, got, reason, tt.ok)
		}
	}
}

func TestCoreNameIsUnique(t *testing.T) {
	// mihomo отвергает весь конфиг при повторяющемся имени прокси.
	seen := map[string]int{}
	first := coreName("🇺🇸", seen)
	second := coreName("🇺🇸", seen)
	third := coreName("🇺🇸", seen)

	if first == second || second == third || first == third {
		t.Fatalf("names not unique: %q, %q, %q", first, second, third)
	}
	if first != "🇺🇸" {
		t.Errorf("first occurrence was renamed to %q — profile names should stay readable", first)
	}
}
