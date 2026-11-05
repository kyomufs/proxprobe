package probe

import (
	"context"

	"github.com/kyomufs/proxprobe/internal/model"
)

// HTTPCheck проверяет узлы реальным запросом через ядро.
type HTTPCheck struct {
	cfg MihomoConfig
}

func (c HTTPCheck) Name() string { return "http" }

func (c HTTPCheck) Run(ctx context.Context, nodes []model.Node) ([]model.Node, []Result, string, error) {
	results, err := Mihomo(ctx, nodes, c.cfg)
	if err != nil {
		return nil, results, "", err
	}

	byID := make(map[string]Result, len(results))
	for _, r := range results {
		byID[r.ID] = r
	}

	alive := make([]model.Node, 0, len(nodes))
	for _, n := range nodes {
		if r, ok := byID[n.ID]; ok && r.OK {
			alive = append(alive, n)
		}
	}
	return alive, results, "", nil
}
