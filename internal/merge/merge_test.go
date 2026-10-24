package merge

import (
	"testing"

	"github.com/kyomufs/proxprobe/internal/model"
)

func node(server string, port int, sources ...string) model.Node {
	n := model.Node{
		Proto: model.ProtoVLESS, Server: server, Port: port,
		UUID: "uuid-1", Network: model.NetTCP, SNI: server,
		Source: sources,
	}
	n.Finalize()
	return n
}

func TestMergeCollapsesDuplicates(t *testing.T) {
	a := []model.Node{node("example.com", 443, "pro1link")}
	b := []model.Node{node("EXAMPLE.com", 443, "goida"), node("other.com", 443, "goida")}

	nodes, report := Merge([][]model.Node{a, b})

	if len(nodes) != 2 {
		t.Fatalf("merged to %d nodes, want 2 (one duplicate must collapse)", len(nodes))
	}
	if report.Input != 3 || report.Unique != 2 || report.Duplicate != 1 {
		t.Errorf("report = %+v; want input 3, unique 2, duplicate 1", report)
	}

	var merged model.Node
	for _, n := range nodes {
		if n.Server == "example.com" {
			merged = n
		}
	}
	if len(merged.Source) != 2 {
		t.Errorf("merged node kept sources %v, want both", merged.Source)
	}
}

func TestMergePrefersCompleteRecord(t *testing.T) {
	poor := node("example.com", 443, "goida") // без reality-полей
	rich := node("example.com", 443, "pro1link")
	rich.Security = model.SecReality
	rich.PublicKey = "pbk"
	rich.ShortID = "sid"
	rich.Fingerprint = "qq"
	rich.Finalize()

	// rich и poor имеют разные ID из-за reality-отпечатка; чтобы проверить
	// именно выбор более полной записи, убираем отпечаток у rich.
	rich.PublicKey = ""
	rich.ShortID = ""
	rich.Fingerprint = "qq"
	rich.Security = model.SecTLS
	rich.Finalize()
	poor.Security = model.SecTLS
	poor.Finalize()

	nodes, _ := Merge([][]model.Node{{poor}, {rich}})
	if len(nodes) != 1 {
		t.Fatalf("got %d nodes, want 1", len(nodes))
	}
	if nodes[0].Fingerprint != "qq" {
		t.Errorf("merge kept the poorer record: fingerprint = %q, want %q", nodes[0].Fingerprint, "qq")
	}
}

func TestMergeReportsCollisions(t *testing.T) {
	a := []model.Node{node("example.com", 443, "pro1link")}
	b := []model.Node{node("example.com", 443, "goida")}

	_, report := Merge([][]model.Node{a, b})

	if len(report.Collisions) != 1 {
		t.Fatalf("got %d collisions, want 1", len(report.Collisions))
	}
	if len(report.Collisions[0].Sources) != 2 {
		t.Errorf("collision lists sources %v, want both", report.Collisions[0].Sources)
	}
}

func TestMergeCountsByProto(t *testing.T) {
	vless := node("a.com", 443, "s")
	trojan := model.Node{Proto: model.ProtoTrojan, Server: "b.com", Port: 443, Password: "p", Source: []string{"s"}}
	trojan.Finalize()

	_, report := Merge([][]model.Node{{vless, trojan}})

	if report.ByProto[model.ProtoVLESS] != 1 || report.ByProto[model.ProtoTrojan] != 1 {
		t.Errorf("ByProto = %v, want one vless and one trojan", report.ByProto)
	}
}

func TestMergeOnEmptyInput(t *testing.T) {
	nodes, report := Merge(nil)
	if len(nodes) != 0 || report.Input != 0 {
		t.Errorf("empty input produced %d nodes and report %+v", len(nodes), report)
	}
}
