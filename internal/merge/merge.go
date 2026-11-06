// Package merge сводит узлы из всех подписок в один список без дубликатов.
package merge

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kyomufs/proxprobe/internal/model"
)

// Mode — что считать одним и тем же сервером при слиянии подписок.
//
// Одна и та же подписка может отдавать один сервер десятком записей: разные
// SNI, разные UUID, разные порты одного адреса. Насколько агрессивно это
// схлопывать — решение пользователя, а не константа в коде.
type Mode string

const (
	// ModeStrict — полный ключ: протокол, адрес, порт, креденшл, транспорт и
	// отпечаток доверия. Схлопываются только настоящие дубликаты.
	ModeStrict Mode = "strict"
	// ModeHost — один узел на адрес сервера: разные порты, креденшлы и
	// транспорты одного адреса считаются зеркалами одного пула.
	ModeHost Mode = "host"
	// ModeNone — не схлопывать ничего: в списке остаются все записи подписок.
	ModeNone Mode = "none"
)

// ParseMode разбирает значение флага --dedupe.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case ModeStrict, ModeHost, ModeNone:
		return Mode(s), nil
	}
	return "", fmt.Errorf("dedupe: неизвестный режим %q (ожидалось strict, host, none)", s)
}

// key — ключ схлопывания. Пустая строка значит "не схлопывать".
func (m Mode) key(n *model.Node) string {
	switch m {
	case ModeHost:
		return strings.ToLower(n.Server)
	case ModeNone:
		return ""
	}
	return n.ID
}

// Report — что произошло при слиянии. Нужен для отчёта: молчаливый дедуп
// скрывает, что подписки пересекаются.
type Report struct {
	Mode       Mode
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

// Merge объединяет узлы, схлопывая их по ключу выбранного режима.
//
// При конфликте побеждает запись с большим числом заполненных полей: обычно
// это Clash-представление, где reality-параметры лежат явными полями, а не
// зашиты в share-ссылку. При равенстве побеждает тот, чей источник раньше в
// конфиге, — порядок в sources.yaml и есть приоритет.
//
// Поле Source всегда объединяется: после слияния видно, из каких подписок
// пришёл узел.
func Merge(groups [][]model.Node, mode Mode) ([]model.Node, Report) {
	report := Report{Mode: mode, ByProto: map[string]int{}}
	byKey := map[string]int{} // ключ схлопывания → индекс в out
	var out []model.Node

	for _, group := range groups {
		for _, n := range group {
			report.Input++
			key := mode.key(&n)
			if key == "" {
				out = append(out, n)
				continue
			}

			idx, seen := byKey[key]
			if !seen {
				byKey[key] = len(out)
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

	out = uniqIDs(out)

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

// uniqIDs разводит совпавшие ID. В режиме none одинаковые записи остаются в
// списке обеими, а проверки и вердикты адресуются по ID — два узла с одним
// ключом получили бы общий результат.
func uniqIDs(nodes []model.Node) []model.Node {
	seen := make(map[string]int, len(nodes))
	for i := range nodes {
		id := nodes[i].ID
		seen[id]++
		if k := seen[id]; k > 1 {
			nodes[i].ID = fmt.Sprintf("%s#%d", id, k)
		}
	}
	return nodes
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
