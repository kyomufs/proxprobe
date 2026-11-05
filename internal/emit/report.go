package emit

import (
	"fmt"
	"strings"
	"time"
)

// Report — сводка прогона. Пишется всегда, в том числе когда подписка не
// обновилась: иначе неудачный прогон невозможно объяснить.
type Report struct {
	Started  time.Time
	Duration time.Duration
	Checks   string
	// HostTUN — на машине включён TUN-клиент: замеры идут через него.
	HostTUN    bool
	Sources    []ReportSource
	Parsed     int
	Skipped    int
	Unique     int
	Duplicates int
	Checked    []ReportCheck
	Written    int
	Nodes      []ReportNode
}

// ReportSource — что произошло с одним источником.
type ReportSource struct {
	Index   int
	Name    string
	Format  string
	Nodes   int
	Skips   int
	Err     string
	DumpErr string
}

// ReportCheck — сколько узлов вошло в проверку и сколько вышло.
type ReportCheck struct {
	Name string
	In   int
	Out  int
	// Note объясняет пропуск проверки; пусто — проверка отработала.
	Note string
}

// ReportNode — строка по узлу: задержка и вердикт последней проверки.
type ReportNode struct {
	Name    string
	Proto   string
	Server  string
	Port    int
	DelayMs float64
	OK      bool
	Check   string
	Err     string
	Source  string
}

// RenderReport собирает report.txt.
func RenderReport(r Report) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "proxprobe %s\n", r.Started.Format("2006-01-02 15:04:05"))
	if r.Duration > 0 {
		fmt.Fprintf(&b, "duration %s\n", r.Duration.Round(time.Millisecond))
	}
	fmt.Fprintf(&b, "checks %s\n", r.Checks)
	if r.HostTUN {
		b.WriteString("host-tun yes: на машине TUN-клиент, замеры идут через него\n")
	}

	b.WriteString("\nsources\n")
	for _, s := range r.Sources {
		switch {
		case s.Err != "":
			fmt.Fprintf(&b, "  [%d] %-24s FAILED: %s\n", s.Index, s.Name, s.Err)
		default:
			fmt.Fprintf(&b, "  [%d] %-24s format=%-10s nodes=%-5d skipped=%d\n",
				s.Index, s.Name, s.Format, s.Nodes, s.Skips)
		}
		if s.DumpErr != "" {
			fmt.Fprintf(&b, "       raw dump failed: %s\n", s.DumpErr)
		}
	}

	fmt.Fprintf(&b, "\nnodes parsed=%d skipped=%d unique=%d duplicates=%d\n",
		r.Parsed, r.Skipped, r.Unique, r.Duplicates)
	for _, c := range r.Checked {
		if c.Note != "" {
			fmt.Fprintf(&b, "%s %d/%d (%s)\n", c.Name, c.Out, c.In, c.Note)
			continue
		}
		fmt.Fprintf(&b, "%s %d/%d\n", c.Name, c.Out, c.In)
	}
	fmt.Fprintf(&b, "written %d\n", r.Written)

	alive := 0
	for _, n := range r.Nodes {
		if n.OK {
			alive++
		}
	}
	fmt.Fprintf(&b, "\nalive %d\n", alive)
	for _, n := range r.Nodes {
		if !n.OK {
			continue
		}
		fmt.Fprintf(&b, "  %5.0fms  %-8s %-42s %s\n",
			n.DelayMs, n.Proto, endpoint(n), n.Name)
	}

	fmt.Fprintf(&b, "\ndead %d\n", len(r.Nodes)-alive)
	for _, n := range r.Nodes {
		if n.OK {
			continue
		}
		reason := n.Err
		if n.Check != "" {
			reason = n.Check + ": " + reason
		}
		fmt.Fprintf(&b, "  %-8s %-42s %-28s %s\n",
			n.Proto, endpoint(n), truncate(n.Name, 28), reason)
	}
	return []byte(b.String())
}

func endpoint(n ReportNode) string {
	return fmt.Sprintf("%s:%d", n.Server, n.Port)
}

// truncate режет длинное имя по рунам: байтовый срез разрезал бы эмодзи.
func truncate(s string, limit int) string {
	r := []rune(s)
	if len(r) <= limit {
		return s
	}
	return string(r[:limit-1]) + "…"
}
