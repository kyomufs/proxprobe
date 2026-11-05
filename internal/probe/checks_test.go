package probe

import "testing"

func TestParseChecksKeepsFixedOrder(t *testing.T) {
	checks, err := ParseChecks("http,tcp", Options{})
	if err != nil {
		t.Fatalf("ParseChecks returned error: %v", err)
	}
	if len(checks) != 2 {
		t.Fatalf("parsed %d checks, want 2", len(checks))
	}
	if checks[0].Name() != "tcp" || checks[1].Name() != "http" {
		t.Fatalf("order = %s,%s: tcp must come first, it filters before the core starts",
			checks[0].Name(), checks[1].Name())
	}
}

func TestParseChecksNoneDisablesEverything(t *testing.T) {
	for _, spec := range []string{"", "none"} {
		checks, err := ParseChecks(spec, Options{})
		if err != nil {
			t.Fatalf("ParseChecks(%q) returned error: %v", spec, err)
		}
		if len(checks) != 0 {
			t.Fatalf("ParseChecks(%q) returned %d checks, want none", spec, len(checks))
		}
	}
}

func TestParseChecksRejectsUnknownAndMixedNone(t *testing.T) {
	for _, spec := range []string{"udp", "tcp,udp", "none,tcp"} {
		if _, err := ParseChecks(spec, Options{}); err == nil {
			t.Errorf("ParseChecks(%q) must fail", spec)
		}
	}
}

func TestParseChecksAppliesOptions(t *testing.T) {
	checks, err := ParseChecks("http", Options{CorePath: "/nix/store/x/mihomo", Jobs: 4})
	if err != nil {
		t.Fatalf("ParseChecks returned error: %v", err)
	}
	http, ok := checks[0].(HTTPCheck)
	if !ok {
		t.Fatalf("check is %T, want HTTPCheck", checks[0])
	}
	if http.cfg.CorePath != "/nix/store/x/mihomo" {
		t.Errorf("core path = %q, want the one from options", http.cfg.CorePath)
	}
	if http.cfg.Concurrency != 4 {
		t.Errorf("concurrency = %d, want 4", http.cfg.Concurrency)
	}
}
