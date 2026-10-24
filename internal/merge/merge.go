// Package merge сводит узлы из всех подписок в один список без дубликатов.
package merge

import (
	"sort"

	"github.com/kyomufs/proxprobe/internal/model"
)

// Report — что произошло при слиянии. Нужен для отчёта: молчаливый дедуп
// скрывает, что подписки пересекаются.
type Report struct {
	Input      int
	Unique     int
	Duplicate  int
	ByProto    map[string]int
	Collisions []Collision
}

// Collision — узел, который встретился в нескольких источниках.
type Collision struct {
	ID      string
	Sources []string
	Name    string
}

// Merge объединяет узлы, схлопывая дубликаты по ID.
//
// При конфликте побеждает запись с большим числом заполненных полей: обычно
// это Clash-представление, где reality-параметры лежат явными полями, а не
// зашиты в share-ссылку. При равенстве побеждает тот, чей источник раньше в
// конфиге, — порядок в sources.yaml и есть приоритет.
//
// Поле Source всегда объединяется: после слияния видно, из каких подписок
// пришёл узел.
func Merge(groups [][]model.Node) ([]model.Node, Report) {
	report := Report{ByProto: map[string]int{}}
	byID := map[string]int{} // ID → индекс в out
	var out []model.Node

	for _, group := range groups {
		for _, n := range group {
			report.Input++
			idx, seen := byID[n.ID]
			if !seen {
				byID[n.ID] = len(out)
				out = append(out, n)
				continue
			}

			report.Duplicate++
			existing := &out[idx]
			existing.Source = unionSorted(existing.Source, n.Source)
			if n.FilledCount() > existing.FilledCount() {
				// Сохраняем объединённые источники и исходные представления
				// обоих вариантов: держим более полную запись, но не теряем
				// Raw менее полной.
				sources := existing.Source
				merged := n
				merged.Source = sources
				merged.Raw = unionRaw(existing.Raw, n.Raw)
				*existing = merged
			} else {
				existing.Raw = unionRaw(existing.Raw, n.Raw)
			}
		}
	}

	// Отчёт о пересечениях: только те узлы, что пришли более чем из одного
	// источника.
	for _, n := range out {
		report.ByProto[n.Proto]++
		if len(n.Source) > 1 {
			report.Collisions = append(report.Collisions, Collision{
				ID: n.ID, Name: n.Name, Sources: n.Source,
			})
		}
	}
	sort.Slice(report.Collisions, func(i, j int) bool {
		return report.Collisions[i].Name < report.Collisions[j].Name
	})

	report.Unique = len(out)
	return out, report
}

// unionSorted объединяет два списка источников без повторов, сохраняя
// порядок: стабильный порядок делает diff между прогонами читаемым.
func unionSorted(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// unionRaw сливает исходные представления по форматам. Ключи не
// перезаписываются: первое значение выигрывает, потому что первым идёт
// приоритетный источник.
func unionRaw(a, b map[string]any) map[string]any {
	if a == nil && b == nil {
		return nil
	}
	out := map[string]any{}
	for k, v := range b {
		out[k] = v
	}
	for k, v := range a {
		out[k] = v
	}
	return out
}
