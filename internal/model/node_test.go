package model

import "testing"

func TestComputeIDDistinguishesRealityKeys(t *testing.T) {
	base := Node{Proto: ProtoVLESS, Server: "example.com", Port: 443, UUID: "u", SNI: "example.com", Network: NetTCP}
	a := base
	a.PublicKey = "KEY_A"
	a.Finalize()
	b := base
	b.PublicKey = "KEY_B"
	b.Finalize()

	if a.ID == b.ID {
		t.Fatalf("two reality nodes with different public keys got the same ID: %s", a.ID)
	}
}

func TestComputeIDMergesSameNodeFromDifferentSources(t *testing.T) {
	a := Node{Proto: ProtoVLESS, Server: "EXAMPLE.com", Port: 443, UUID: "u", Network: NetTCP, Source: []string{"pro1link"}}
	a.Finalize()
	b := Node{Proto: ProtoVLESS, Server: "example.com", Port: 443, UUID: "u", Network: NetTCP, Source: []string{"goida"}}
	b.Finalize()

	if a.ID != b.ID {
		t.Fatalf("same node from different sources got different IDs:\n  %s\n  %s", a.ID, b.ID)
	}
}

func TestComputeIDSeparatesPorts(t *testing.T) {
	a := Node{Proto: ProtoVLESS, Server: "example.com", Port: 443, UUID: "u"}
	a.Finalize()
	b := Node{Proto: ProtoVLESS, Server: "example.com", Port: 8443, UUID: "u"}
	b.Finalize()

	if a.ID == b.ID {
		t.Fatal("nodes on different ports got the same ID")
	}
}

func TestFinalizeDefaults(t *testing.T) {
	n := Node{Proto: ProtoTrojan, Server: "example.com", Port: 443, Password: "p"}
	n.Finalize()

	if n.Network != NetTCP {
		t.Errorf("network = %q, want %q", n.Network, NetTCP)
	}
	if n.Security != SecTLS {
		t.Errorf("security = %q, want %q for trojan without explicit security", n.Security, SecTLS)
	}
	if n.Name == "" {
		t.Error("name was not synthesised")
	}
}

func TestFinalizeKeepsSocks5Plain(t *testing.T) {
	n := Node{Proto: ProtoSocks5, Server: "1.2.3.4", Port: 1080}
	n.Finalize()

	if n.Security != SecNone {
		t.Errorf("security = %q, want %q: socks5 without TLS must stay plain", n.Security, SecNone)
	}
}

func TestFinalizeNormalisesPath(t *testing.T) {
	n := Node{Proto: ProtoVLESS, Server: "example.com", Port: 443, UUID: "u", Network: NetWS, Path: "sg-melbi"}
	n.Finalize()

	if n.Path != "/sg-melbi" {
		t.Errorf("path = %q, want %q", n.Path, "/sg-melbi")
	}
}

func TestFilledCountPrefersCompleteNode(t *testing.T) {
	poor := Node{Proto: ProtoVLESS, Server: "example.com", Port: 443, UUID: "u", Name: "x"}
	poor.Finalize()
	rich := Node{
		Proto: ProtoVLESS, Server: "example.com", Port: 443, UUID: "u", Name: "x",
		SNI: "example.com", PublicKey: "pbk", ShortID: "sid", Fingerprint: "qq",
		Flow: "xtls-rprx-vision", Network: NetTCP, Security: SecReality,
	}
	rich.Finalize()

	if rich.FilledCount() <= poor.FilledCount() {
		t.Fatalf("rich node counted %d fields, poor node %d — merge would keep the wrong one",
			rich.FilledCount(), poor.FilledCount())
	}
}

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		in   string
		host string
		port int
	}{
		{"example.com:443", "example.com", 443},
		{"1.2.3.4:1080", "1.2.3.4", 1080},
		{"[2001:db8::1]:8443", "2001:db8::1", 8443},
	}
	for _, tt := range tests {
		host, port, err := ParseEndpoint(tt.in)
		if err != nil {
			t.Errorf("ParseEndpoint(%q) returned error: %v", tt.in, err)
			continue
		}
		if host != tt.host || port != tt.port {
			t.Errorf("ParseEndpoint(%q) = %q, %d; want %q, %d", tt.in, host, port, tt.host, tt.port)
		}
	}

	if _, _, err := ParseEndpoint("example.com"); err == nil {
		t.Error("ParseEndpoint accepted an endpoint without a port")
	}
}
