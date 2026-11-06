// Command proxprobe собирает подписку из sources.yaml, проверяет узлы и
// пишет профиль для клиента вместе с отчётом.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/kyomufs/proxprobe/internal/detect"
	"github.com/kyomufs/proxprobe/internal/emit"
	"github.com/kyomufs/proxprobe/internal/fetch"
	"github.com/kyomufs/proxprobe/internal/merge"
	"github.com/kyomufs/proxprobe/internal/model"
	"github.com/kyomufs/proxprobe/internal/parse"
	"github.com/kyomufs/proxprobe/internal/probe"
	"github.com/kyomufs/proxprobe/internal/sources"
)

// version подставляется при сборке: -ldflags "-X main.version=..."
var version = "dev"

const usage = `proxprobe — собирает подписку из sources.yaml и проверяет узлы.

Использование:
  proxprobe [flags]

Флаги:
  --config PATH   sources.yaml (по умолчанию $XDG_CONFIG_HOME/proxprobe/sources.yaml)
  --out DIR       каталог для sub.yaml и report.txt (по умолчанию $XDG_DATA_HOME/proxprobe)
  --check LIST    проверки через запятую: none, tcp, http (по умолчанию tcp,http)
  --dedupe MODE   что считать дубликатом: strict, host, none (по умолчанию strict)
  --core NAME     бинарь ядра mihomo (по умолчанию mihomo)
  --jobs N        сколько узлов HTTP-проверка проверяет одновременно (по умолчанию 16)
  --dump-raw DIR  сохранить исходные тела подписок в DIR
  --version       напечатать версию

Коды возврата:
  0 — sub.yaml записан, хотя бы один узел прошёл проверки
  1 — живых узлов нет (sub.yaml не тронут, report.txt обновлён)
  2 — ошибка запуска: конфиг, флаги, ядро
`

type options struct {
	config  string
	out     string
	check   string
	dedupe  string
	core    string
	jobs    int
	dumpRaw string
	version bool
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	opts, err := parseArgs(args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Print(usage)
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "proxprobe: %v\n\n%s", err, usage)
		return 2
	}
	if opts.version {
		fmt.Printf("proxprobe %s\n", version)
		return 0
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	report := &emit.Report{Started: time.Now(), Checks: opts.check}
	code, runErr := execute(ctx, opts, report)
	report.Duration = time.Since(report.Started)

	// Отчёт пишется всегда, когда конфиг прочитан: без него неудачный прогон
	// невозможно объяснить. Ошибка конфига сюда не доходит — писать отчёт
	// поверх прошлого было бы хуже, чем не писать ничего.
	if len(report.Sources) > 0 {
		if err := writeReport(opts.out, report); err != nil {
			fmt.Fprintf(os.Stderr, "proxprobe: cannot write report: %v\n", err)
			if code == 0 {
				code = 2
			}
		}
	}
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "proxprobe: %v\n", runErr)
	}
	return code
}

func parseArgs(args []string) (options, error) {
	var opts options
	fs := flag.NewFlagSet("proxprobe", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&opts.config, "config", defaultConfigPath(), "path to sources.yaml")
	fs.StringVar(&opts.out, "out", defaultDataDir(), "output directory")
	fs.StringVar(&opts.check, "check", "tcp,http", "checks: none, tcp, http")
	fs.StringVar(&opts.dedupe, "dedupe", string(merge.ModeStrict), "duplicate rule: strict, host, none")
	fs.StringVar(&opts.core, "core", "mihomo", "core binary name")
	fs.IntVar(&opts.jobs, "jobs", probe.HTTPJobs, "HTTP check concurrency")
	fs.StringVar(&opts.dumpRaw, "dump-raw", "", "save raw source bodies to this directory")
	fs.BoolVar(&opts.version, "version", false, "print version")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if fs.NArg() > 0 {
		return options{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if _, err := merge.ParseMode(opts.dedupe); err != nil {
		return options{}, err
	}
	return opts, nil
}

func defaultConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "sources.yaml"
	}
	return filepath.Join(dir, "proxprobe", "sources.yaml")
}

func defaultDataDir() string {
	if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
		return filepath.Join(dir, "proxprobe")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "out"
	}
	return filepath.Join(home, ".local", "share", "proxprobe")
}

// verdict — результат последней проверки, которую узел прошёл или не прошёл.
type verdict struct {
	check string
	res   probe.Result
}

func execute(ctx context.Context, opts options, report *emit.Report) (int, error) {
	list, err := sources.Load(opts.config)
	if err != nil {
		return 2, err
	}

	fetched := fetch.All(ctx, list, fetch.Options{DumpDir: opts.dumpRaw})
	var groups [][]model.Node
	failed := 0

	for _, r := range fetched {
		stat := emit.ReportSource{Index: r.Index + 1, Name: r.Source.Name()}
		if r.Err != nil {
			stat.Err = r.Err.Error()
			failed++
			report.Sources = append(report.Sources, stat)
			continue
		}

		format, body := detect.Sniff(r.Body)
		parsed := parseAs(format, body, r.Source.Name())
		stat.Format = string(format)
		stat.Nodes = len(parsed.Nodes)
		stat.Skips = len(parsed.Skips)
		if r.DumpErr != nil {
			stat.DumpErr = r.DumpErr.Error()
		}
		report.Sources = append(report.Sources, stat)
		report.Parsed += len(parsed.Nodes)
		report.Skipped += len(parsed.Skips)
		groups = append(groups, parsed.Nodes)
	}

	if len(fetched) > 0 && failed == len(fetched) {
		return 1, errors.New("all sources failed")
	}

	mode, err := merge.ParseMode(opts.dedupe)
	if err != nil {
		return 2, err
	}
	nodes, merged := merge.Merge(groups, mode)
	report.Dedupe = string(mode)
	report.Unique = merged.Unique
	report.Duplicates = merged.Duplicate
	if len(nodes) == 0 {
		return 1, errors.New("no proxies parsed from sources")
	}

	tun := probe.DetectHostTUN()
	report.HostTUN = tun
	if tun {
		fmt.Fprintln(os.Stderr, "proxprobe: host TUN detected, measurements go through it")
	}

	checks, err := probe.ParseChecks(opts.check, probe.Options{
		CorePath: opts.core,
		Jobs:     opts.jobs,
		Progress: progressToStderr,
		HostTUN:  tun,
	})
	if err != nil {
		return 2, err
	}

	all := nodes
	verdicts := make(map[string]verdict, len(all))
	for _, c := range checks {
		input := len(nodes)
		alive, results, note, err := c.Run(ctx, nodes)
		if err != nil {
			return 2, fmt.Errorf("%s check: %w", c.Name(), err)
		}
		if note != "" {
			fmt.Fprintf(os.Stderr, "proxprobe: %s %s\n", c.Name(), note)
		}
		for _, r := range results {
			verdicts[r.ID] = verdict{check: c.Name(), res: r}
		}
		report.Checked = append(report.Checked, emit.ReportCheck{
			Name: c.Name(), In: input, Out: len(alive), Note: note,
		})
		nodes = alive
	}
	if len(checks) == 0 {
		for _, n := range all {
			verdicts[n.ID] = verdict{res: probe.Result{OK: true}}
		}
	}

	sortByDelay(nodes, verdicts)
	report.Nodes = reportNodes(all, verdicts)

	if len(nodes) == 0 {
		// Прошлый профиль не перезаписывается: пустой sub.yaml в клиенте
		// выглядит как поломка, а старый рабочий набор лучше нуля.
		return 1, fmt.Errorf("no nodes passed checks (%s); %s left untouched", opts.check, emit.SubFile)
	}

	body, err := emit.Subscription(nodes)
	if err != nil {
		return 2, err
	}
	path := filepath.Join(opts.out, emit.SubFile)
	if err := writeAtomic(path, body); err != nil {
		return 2, fmt.Errorf("cannot write %s: %w", path, err)
	}
	report.Written = len(nodes)
	fmt.Printf("%s: %d nodes\n", path, len(nodes))
	return 0, nil
}

func parseAs(format detect.Format, body []byte, source string) *parse.Result {
	switch format {
	case detect.FormatLinks, detect.FormatLinksB64:
		return parse.Links(body, source)
	case detect.FormatClash:
		return parse.Clash(body, source)
	case detect.FormatXrayBundles:
		return parse.XrayBundles(body, source)
	case detect.FormatXrayConfig:
		return parse.XrayConfig(body, source)
	case detect.FormatSingbox:
		return parse.Singbox(body, source)
	}
	return &parse.Result{}
}

// sortByDelay ставит живые узлы по возрастанию задержки; при равной
// задержке — по имени, чтобы порядок был стабилен между прогонами.
func sortByDelay(nodes []model.Node, verdicts map[string]verdict) {
	sort.SliceStable(nodes, func(i, j int) bool {
		vi, vj := verdicts[nodes[i].ID], verdicts[nodes[j].ID]
		if vi.res.OK && vj.res.OK && vi.res.DelayMs != vj.res.DelayMs {
			return vi.res.DelayMs < vj.res.DelayMs
		}
		return nodes[i].Name < nodes[j].Name
	})
}

// reportNodes собирает строки отчёта: живые по задержке, мёртвые по имени.
func reportNodes(all []model.Node, verdicts map[string]verdict) []emit.ReportNode {
	out := make([]emit.ReportNode, 0, len(all))
	for _, n := range all {
		v := verdicts[n.ID]
		out = append(out, emit.ReportNode{
			Name: n.Name, Proto: string(n.Proto), Server: n.Server, Port: n.Port,
			DelayMs: v.res.DelayMs, OK: v.res.OK, Check: v.check, Err: v.res.Error,
			Source: joinSources(n.Source),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].OK != out[j].OK {
			return out[i].OK
		}
		if out[i].OK && out[i].DelayMs != out[j].DelayMs {
			return out[i].DelayMs < out[j].DelayMs
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func joinSources(list []string) string {
	if len(list) == 0 {
		return ""
	}
	out := list[0]
	for _, s := range list[1:] {
		out += "," + s
	}
	return out
}

func progressToStderr(done, total int) {
	fmt.Fprintf(os.Stderr, "http: checked %d/%d\n", done, total)
}

func writeReport(dir string, report *emit.Report) error {
	path := filepath.Join(dir, emit.ReportFile)
	return writeAtomic(path, emit.RenderReport(*report))
}

// writeAtomic пишет файл через временный и переименование: прерванный
// прогон не оставляет клиенту половину профиля.
func writeAtomic(path string, body []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)

	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
