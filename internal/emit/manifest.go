package emit

import (
	"encoding/json"
	"time"

	"github.com/kyomufs/proxprobe/internal/model"
)

// ManifestFile — манифест профиля: что именно ядро получило и откуда.
//
// Профиль ядра — это список имён, по которым ничего не известно: имя узла
// может быть переименовано при уникализации, а подписка, из которой он
// пришёл, в профиле не записана вовсе. Панель, которая показывает узлы по
// подпискам, без манифеста угадывала бы по префиксу имени.
const ManifestFile = "nodes.json"

// Manifest — содержимое манифеста.
type Manifest struct {
	Generated string         `json:"generated"`
	Nodes     []ManifestNode `json:"nodes"`
}

// ManifestNode — один узел так, как он лежит в профиле.
type ManifestNode struct {
	Name    string   `json:"name"`
	Proto   string   `json:"proto"`
	Server  string   `json:"server"`
	Port    int      `json:"port"`
	Sources []string `json:"sources,omitempty"`
}

// RenderManifest собирает манифест тем же проходом, что и профиль: имена
// совпадают с профилем, включая суффиксы уникализации.
func RenderManifest(nodes []model.Node) ([]byte, error) {
	built := buildNamedProxies(nodes, MihomoGroup, directName)

	doc := Manifest{
		Generated: time.Now().Format(time.RFC3339),
		Nodes:     make([]ManifestNode, 0, len(built)),
	}
	for _, b := range built {
		doc.Nodes = append(doc.Nodes, ManifestNode{
			Name:    b.name,
			Proto:   b.node.Proto,
			Server:  b.node.Server,
			Port:    b.node.Port,
			Sources: b.node.Source,
		})
	}
	return json.MarshalIndent(doc, "", "  ")
}
