package probe

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestWriteMihomoConfigSetsDNS закрывает случай, из-за которого вся проба
// мерила чужой туннель: без блока DNS ядро берёт системный резолвер, а под
// TUN-клиентом тот отдаёт fake-IP, и цель запроса недостижима с узла.
func TestWriteMihomoConfigSetsDNS(t *testing.T) {
	cfg := Defaults()
	cfg.DNS = []string{"9.9.9.9"}
	path := filepath.Join(t.TempDir(), "config.yaml")

	if _, _, err := writeMihomoConfig(path, duplicateNameNodes(), cfg); err != nil {
		t.Fatalf("writeMihomoConfig returned error: %v", err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read generated config: %v", err)
	}
	var doc struct {
		DNS struct {
			Enable       bool     `yaml:"enable"`
			EnhancedMode string   `yaml:"enhanced-mode"`
			Nameserver   []string `yaml:"nameserver"`
		} `yaml:"dns"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("generated config does not parse: %v", err)
	}

	if !doc.DNS.Enable {
		t.Fatal("dns block is disabled: the core would use the system resolver")
	}
	if doc.DNS.EnhancedMode != "normal" {
		t.Errorf("enhanced-mode is %q, want normal: fake-ip would hide the real node address", doc.DNS.EnhancedMode)
	}
	if len(doc.DNS.Nameserver) != 1 || doc.DNS.Nameserver[0] != "9.9.9.9" {
		t.Errorf("nameserver = %v, want the servers from the config", doc.DNS.Nameserver)
	}
}

// TestFakeIPRejected — адрес из 198.18.0.0/15 принадлежит чужому TUN, а не
// узлу: соединение по нему поднимет туннель хоста, и «порт открыт» будет
// неправдой.
func TestFakeIPRejected(t *testing.T) {
	for _, addr := range []string{"198.18.0.1", "198.19.255.254"} {
		if ip := net.ParseIP(addr); ip == nil || !fakeIPNet.Contains(ip) {
			t.Errorf("%s must be treated as fake-ip", addr)
		}
	}
	for _, addr := range []string{"8.8.8.8", "104.16.72.101", "198.17.0.1"} {
		if ip := net.ParseIP(addr); ip != nil && fakeIPNet.Contains(ip) {
			t.Errorf("%s is a real address, not fake-ip", addr)
		}
	}
}

// TestResolverForEmptyKeepsSystem — без явных серверов резолвер обязан
// остаться системным: иначе прогон на машине без внешнего DNS не проверит
// ничего вовсе.
func TestResolverForEmptyKeepsSystem(t *testing.T) {
	if got := resolverFor(nil); got != net.DefaultResolver {
		t.Fatal("empty server list must keep the system resolver")
	}
	if got := resolverFor([]string{"1.1.1.1"}); got == net.DefaultResolver {
		t.Fatal("explicit servers must replace the system resolver")
	}
}
