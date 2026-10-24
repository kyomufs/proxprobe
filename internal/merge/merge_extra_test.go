package merge

import (
	"testing"

	"github.com/kyomufs/proxprobe/internal/model"
)

func TestMergeCountsByProtoExtra(t *testing.T) {
	vless := node("a.com", 443, "s")
	trojan := model.Node{Proto: model.ProtoTrojan, Server: "b.com", Port: 443, Password: "p", Source: []string{"s"}}
	trojan.Finalize()

	_, report := Merge([][]model.Node{{vless, trojan}})

	if report.ByProto[model.ProtoVLESS] != 1 || report.ByProto[model.ProtoTrojan] != 1 {
		t.Errorf("ByProto = %v, want one vless and one trojan", report.ByProto)
	}
}

func TestMergeEmptyInputExtra(t *testing.T) {
	nodes, report := Merge(nil)
	if len(nodes) != 0 || report.Input != 0 {
		t.Errorf("empty input produced %d nodes and report %+v", len(nodes), report)
	}
}
