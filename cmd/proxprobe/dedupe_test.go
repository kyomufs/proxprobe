package main

import (
	"testing"

	"github.com/kyomufs/proxprobe/internal/model"
)

func poolNode(name, server string, port int, delay float64, status string) model.Node {
	n := model.Node{Proto: model.ProtoVLESS, Name: name, Server: server, Port: port,
		UUID: "00000000-0000-0000-0000-000000000000"}
	n.Finalize()
	n.Raw = map[string]any{"delay_ms": delay, "status": status}
	return n
}

func TestDedupeByPoolKeepsFastest(t *testing.T) {
	nodes := []model.Node{
		poolNode("slow clone", "212.193.27.232", 443, 900, model.StatusAlive),
		poolNode("fast clone", "212.193.27.232", 443, 300, model.StatusAlive),
		poolNode("other ip", "1.2.3.4", 443, 400, model.StatusAlive),
	}
	got := dedupeByPool(nodes, 1)
	if len(got) != 2 {
		t.Fatalf("dedupe kept %d nodes, want 2 pools", len(got))
	}
	names := map[string]bool{}
	for _, n := range got {
		names[n.Name] = true
	}
	if !names["fast clone"] {
		t.Errorf("fastest node of the pool was dropped: %v", names)
	}
	if names["slow clone"] {
		t.Errorf("slower clone survived: %v", names)
	}
}

func TestDedupeByPoolDropsThrottledPool(t *testing.T) {
	// 429 пришёл с одного узла пула — значит лимит исчерпан у всего пула:
	// быстрый сосед того же server:port сгорит вместе с ним.
	nodes := []model.Node{
		poolNode("throttled clone", "212.193.27.232", 443, 200, model.StatusThrottled),
		poolNode("alive clone", "212.193.27.232", 443, 300, model.StatusAlive),
		poolNode("clean", "1.2.3.4", 443, 400, model.StatusAlive),
	}
	got := dedupeByPool(nodes, 1)
	if len(got) != 1 {
		t.Fatalf("dedupe kept %d nodes, want only the clean pool", len(got))
	}
	if got[0].Name != "clean" {
		t.Errorf("wrong pool survived: %v", got[0].Name)
	}
}

func TestDedupeByPoolKeepN(t *testing.T) {
	nodes := []model.Node{
		poolNode("a", "212.193.27.232", 443, 900, model.StatusAlive),
		poolNode("b", "212.193.27.232", 443, 300, model.StatusAlive),
		poolNode("c", "212.193.27.232", 443, 600, model.StatusAlive),
	}
	got := dedupeByPool(nodes, 2)
	if len(got) != 2 {
		t.Fatalf("keep=2 kept %d nodes, want 2", len(got))
	}
	if got[0].Name != "b" || got[1].Name != "c" {
		t.Errorf("wrong keep order: %s, %s", got[0].Name, got[1].Name)
	}
}

func TestDedupeByPoolDisabled(t *testing.T) {
	nodes := []model.Node{
		poolNode("a", "212.193.27.232", 443, 900, model.StatusAlive),
		poolNode("b", "212.193.27.232", 443, 300, model.StatusAlive),
	}
	if got := dedupeByPool(nodes, 0); len(got) != 2 {
		t.Errorf("keep=0 dropped nodes: %d", len(got))
	}
}
