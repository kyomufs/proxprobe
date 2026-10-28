// Command proxprobe собирает серверы из разнородных подписок, проверяет их
// живость через ядро mihomo и выгружает результат в форматы подписок.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/kyomufs/proxprobe/internal/detect"
	"github.com/kyomufs/proxprobe/internal/emit"
	"github.com/kyomufs/proxprobe/internal/fetch"
	"github.com/kyomufs/proxprobe/internal/layout"
	"github.com/kyomufs/proxprobe/internal/merge"
	"github.com/kyomufs/proxprobe/internal/model"
	"github.com/kyomufs/proxprobe/internal/parse"
	"github.com/kyomufs/proxprobe/internal/probe"
	"github.com/kyomufs/proxprobe/internal/sources"
)

// buildVersion подставляется линкером при сборке пакета.
var buildVersion = "dev"

const usage = `proxprobe — сбор, проверка и конвертация прокси-подписок

использование:
  proxprobe <команда> [флаги]

команды:
  fetch    скачать подписки в raw/
  parse    разобрать скачанное в nodes/
  merge    слить узлы из всех источников без дубликатов
  ping     проверить TCP-доступность узлов
  probe    проверить узлы реальным запросом через ядро mihomo
  export   выгрузить результат в clash/best
  all      выполнить весь конвейер подряд
  version  напечатать версию

флаги:
  --config    путь к sources.yaml (по умолчанию ./sources.yaml)
  --workdir   рабочий каталог (по умолчанию ./out)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "fetch":
		err = cmdFetch(ctx, args)
	case "parse":
		err = cmdParse(ctx, args)
	case "merge":
		err = cmdMerge(ctx, args)
	case "ping":
		err = cmdPing(ctx, args)
	case "probe":
		err = cmdProbe(ctx, args)
	case "export":
		err = cmdExport(ctx, args)
	case "all":
		err = cmdAll(ctx, args)
	case "version":
		fmt.Printf("proxprobe %s\n", buildVersion)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "proxprobe: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "proxprobe %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func cmdFetch(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	cb := bindCommon(fs)
	refresh := fs.Bool("refresh", false, "re-download even if raw file exists")
	attempts := fs.Int("attempts", fetch.DefaultAttempts, "attempts per source before giving up")
	c, err := cb.parse(fs, args)
	if err != nil {
		return err
	}

	list, err := sources.Load(c.config)
	if err != nil {
		return err
	}
	list = sources.Active(list)

	results := fetch.All(ctx, list, fetch.Options{
		RawDir:   layout.DirPath(c.workdir, layout.RawDir),
		Refresh:  *refresh,
		Attempts: *attempts,
	})

	var failed int
	for _, r := range results {
		if r.Error != nil {
			failed++
			fmt.Printf("  %-20s FAILED  %v\n", r.ID, r.Error)
			continue
		}
		fmt.Printf("  %-20s %8d bytes  sha256:%s\n", r.ID, r.Size, r.SHA256[:12])
	}
	if failed == len(results) {
		return fmt.Errorf("every source failed")
	}
	return nil
}

func cmdParse(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("parse", flag.ExitOnError)
	cb := bindCommon(fs)
	only := fs.String("source", "", "parse only this source id")
	c, err := cb.parse(fs, args)
	if err != nil {
		return err
	}

	list, err := sources.Load(c.config)
	if err != nil {
		return err
	}

	nodesDir := layout.DirPath(c.workdir, layout.NodesDir)
	if err := os.MkdirAll(nodesDir, 0o755); err != nil {
		return err
	}

	var total int
	var skipPath = layout.SkipPath(c.workdir)
	if err := layout.EnsurePath(skipPath); err != nil {
		return err
	}
	skipFile, err := os.Create(skipPath)
	if err != nil {
		return err
	}
	defer skipFile.Close()

	for _, s := range sources.Active(list) {
		if *only != "" && s.ID != *only {
			continue
		}
		path := layout.RawPath(c.workdir, s.ID)
		body, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("  %-20s SKIPPED (no raw file)\n", s.ID)
			continue
		}

		format, decoded := detect.Sniff(body)
		res := parseAs(format, decoded, s.ID)

		outPath := layout.NodesPath(c.workdir, s.ID)
		if err := writeNodesJSONL(outPath, res.Nodes); err != nil {
			return err
		}
		total += len(res.Nodes)

		fmt.Printf("  %-20s format=%-12s nodes=%5d skips=%d\n",
			s.ID, format, len(res.Nodes), len(res.Skips))
		for _, sk := range res.Skips {
			fmt.Fprintf(skipFile, "%s\t%s\t%s\n", s.ID, sk.Reason, sk.Line)
		}
	}

	fmt.Printf("parsed %d nodes total\n", total)
	return nil
}

// parseAs направляет тело подписки в парсер нужного формата.
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
	res := &parse.Result{}
	return res
}

func writeNodesJSONL(path string, nodes []model.Node) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, n := range nodes {
		if err := enc.Encode(n); err != nil {
			return err
		}
	}
	return nil
}

func readNodesJSONL(path string) ([]model.Node, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var nodes []model.Node
	dec := json.NewDecoder(f)
	for dec.More() {
		var n model.Node
		if err := dec.Decode(&n); err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

// loadNodeGroups читает все разобранные подписки в порядке конфига: порядок
// источников задаёт приоритет при слиянии дубликатов.
func loadNodeGroups(config, workdir string) ([][]model.Node, []string, error) {
	list, err := sources.Load(config)
	if err != nil {
		return nil, nil, err
	}
	var groups [][]model.Node
	var ids []string
	for _, s := range sources.Active(list) {
		path := layout.NodesPath(workdir, s.ID)
		nodes, err := readNodesJSONL(path)
		if err != nil {
			continue // источник не разобран — это не ошибка всего запуска
		}
		groups = append(groups, nodes)
		ids = append(ids, s.ID)
	}
	if len(groups) == 0 {
		return nil, nil, fmt.Errorf("no parsed sources in %s/nodes; run parse first", workdir)
	}
	return groups, ids, nil
}

func cmdMerge(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("merge", flag.ExitOnError)
	cb := bindCommon(fs)
	c, err := cb.parse(fs, args)
	if err != nil {
		return err
	}

	groups, ids, err := loadNodeGroups(c.config, c.workdir)
	if err != nil {
		return err
	}
	nodes, report := merge.Merge(groups)

	outPath := layout.MergedPath(c.workdir)
	if err := layout.EnsurePath(outPath); err != nil {
		return err
	}
	if err := writeNodesJSONL(outPath, nodes); err != nil {
		return err
	}

	fmt.Printf("sources: %s\n", strings.Join(ids, ", "))
	fmt.Printf("merged: input=%d unique=%d duplicates=%d\n",
		report.Input, report.Unique, report.Duplicate)
	for proto, count := range report.ByProto {
		fmt.Printf("  %-12s %5d\n", proto, count)
	}
	if len(report.Collisions) > 0 {
		fmt.Printf("overlapping nodes: %d (first three: ", len(report.Collisions))
		for i, col := range report.Collisions {
			if i == 3 {
				break
			}
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Printf("%s", strings.Join(col.Sources, "+"))
		}
		fmt.Println(")")
	}
	return nil
}

func cmdPing(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	cb := bindCommon(fs)
	concurrency := fs.Int("concurrency", 200, "parallel dials")
	timeout := fs.Duration("timeout", 2*time.Second, "dial timeout")
	c, err := cb.parse(fs, args)
	if err != nil {
		return err
	}

	nodes, err := readNodesJSONL(layout.MergedPath(c.workdir))
	if err != nil {
		return fmt.Errorf("run merge first: %w", err)
	}

	results := probe.TCP(ctx, nodes, *concurrency, *timeout)
	if err := probe.WriteJSONL(layout.TCPPath(c.workdir), results); err != nil {
		return err
	}

	ok, dnsFail, dialFail := probe.Summarise(results)
	fmt.Printf("tcp probe: alive=%d dns_failed=%d dial_failed=%d of %d\n",
		ok, dnsFail, dialFail, len(results))
	return nil
}

func cmdProbe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	cb := bindCommon(fs)
	core := fs.String("core", "mihomo", "path to core binary")
	testURL := fs.String("url", "", "URL to fetch through each node")
	timeout := fs.Duration("timeout", 0, "per-node timeout")
	concurrency := fs.Int("concurrency", 16, "parallel node probes")

	if *timeout == 0 {
		*timeout = 5 * time.Second
	}
	c, err := cb.parse(fs, args)
	if err != nil {
		return err
	}

	nodes, err := readNodesJSONL(layout.MergedPath(c.workdir))
	if err != nil {
		return fmt.Errorf("run merge first: %w", err)
	}

	cfg := probe.Defaults()
	cfg.CorePath = *core
	cfg.WorkDir = c.workdir
	cfg.Timeout = *timeout
	cfg.Concurrency = *concurrency
	if *testURL != "" {
		cfg.TestURL = *testURL
	}
	// Прогон на тысячах узлов идёт минутами; без отчёта о ходе он
	// неотличим от зависания.
	cfg.Progress = func(done, total int) {
		fmt.Printf("\r  probing %d/%d…", done, total)
	}

	results, err := probe.Mihomo(ctx, nodes, cfg)
	fmt.Print("\r")
	if err != nil {
		return err
	}
	if err := probe.WriteResults(layout.HTTPPath(c.workdir), results); err != nil {
		return err
	}

	counts := map[string]int{}
	for _, r := range results {
		status := r.Status
		if status == "" {
			// Запись без статуса возможна только у старых результатов;
			// здесь её источник — тот же прогон, поэтому fallback.
			status = probe.StatusDead
		}
		counts[status]++
	}
	fmt.Printf("http probe via %s: alive=%d throttled=%d forbidden=%d dead=%d\n",
		*core, counts[probe.StatusAlive], counts[probe.StatusThrottled],
		counts[probe.StatusForbidden], counts[probe.StatusDead])
	if counts[probe.StatusAlive] == 0 && len(results) > 0 {
		return fmt.Errorf("no node answered through the core")
	}
	return nil
}

func cmdExport(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	cb := bindCommon(fs)
	target := fs.String("target", "all", "merged|sorted|all")
	keepPools := fs.Int("keep-pools", 1, "max nodes kept per server:port pool (0 = no dedup)")
	c, err := cb.parse(fs, args)
	if err != nil {
		return err
	}

	nodes, err := readNodesJSONL(layout.MergedPath(c.workdir))
	if err != nil {
		return fmt.Errorf("run merge first: %w", err)
	}
	before := len(nodes)
	nodes = attachDelays(c.workdir, nodes)
	nodes = dedupeByPool(nodes, *keepPools)
	if *keepPools > 0 {
		fmt.Fprintf(os.Stderr, "  pools: %d nodes -> %d (keep %d per server:port)\n",
			before, len(nodes), *keepPools)
	}

	targets := []string{"merged", "sorted"}
	if *target != "all" {
		targets = strings.Split(*target, ",")
	}

	paths, err := emit.WriteAll(layout.ClashDirPath(c.workdir), nodes, targets)
	if err != nil {
		return err
	}
	for _, p := range paths {
		info, _ := os.Stat(p)
		fmt.Printf("  %-40s %8d bytes\n", p, info.Size())
	}
	return nil
}

// attachDelays переносит замеры HTTP-пробы в Raw узлов: экспортёр best
// отбирает и сортирует именно по ним.
//
// Узел считается живым, только если HTTP-запрос прошёл И TCP-этап до него
// тоже дал коннект. Без второй проверки мёртвый узел с refused-портом
// попадал в sorted.yaml: проба ходит через ядро, и при неверно выбранном
// маршруте запрос отвечает 2xx напрямую, а задержка принадлежит каналу
// хоста, а не узлу.
func attachDelays(workdir string, nodes []model.Node) []model.Node {
	results, err := probe.ReadResults(layout.HTTPPath(workdir))
	if err != nil {
		// HTTP-пробы не было: живость берётся из TCP, иначе sorted.yaml
		// остаётся пустым скелетом, хотя порты открыты и замеры есть.
		return tcpDelays(workdir, nodes)
	}
	reachable, hasTCP := tcpReachable(workdir)

	type verdict struct {
		delay  float64
		status string
	}
	verdicts := map[string]verdict{}
	for _, r := range results {
		if r.OK {
			if hasTCP && !reachable[r.ID] {
				continue
			}
			verdicts[r.ID] = verdict{delay: r.DelayMs, status: probe.StatusAlive}
			continue
		}
		// 429 и 403 — это ответ цели, а не обрыв. Задержка у них измерена,
		// и статус нужен экспортёру, чтобы пул с исчерпанной квотой выпал
		// целиком, а не притворился живым.
		if r.Status == probe.StatusThrottled || r.Status == probe.StatusForbidden {
			verdicts[r.ID] = verdict{delay: r.DelayMs, status: r.Status}
		}
	}
	for i := range nodes {
		v, ok := verdicts[nodes[i].ID]
		if !ok {
			continue
		}
		if nodes[i].Raw == nil {
			nodes[i].Raw = map[string]any{}
		}
		nodes[i].Raw["delay_ms"] = v.delay
		nodes[i].Raw["status"] = v.status
	}
	return nodes
}

// tcpDelays переносит TCP-замеры в Raw узлов, когда HTTP-пробы не было.
//
// Живым здесь считается узел с открытым портом: это ровно то, что знает
// TCP-этап. Статус тоже ставится — StatusAlive, — иначе Sorted отбросит
// узел по отсутствию статуса и профиль останется пустым. delay_ms берётся
// из dial_ms: другого замера в этом режиме нет.
func tcpDelays(workdir string, nodes []model.Node) []model.Node {
	items, err := probe.ReadTCPResults(layout.TCPPath(workdir))
	if err != nil {
		return nodes
	}
	byID := make(map[string]probe.TCPResult, len(items))
	for _, r := range items {
		byID[r.ID] = r
	}
	for i := range nodes {
		r, ok := byID[nodes[i].ID]
		if !ok || !r.OK {
			continue
		}
		if nodes[i].Raw == nil {
			nodes[i].Raw = map[string]any{}
		}
		nodes[i].Raw["delay_ms"] = r.DialMs
		nodes[i].Raw["status"] = model.StatusAlive
	}
	return nodes
}

// dedupeByPool оставляет в профиле не больше keep лучших узлов на пул
// server:port.
//
// Сервисы обычно считают квоту на пул: 48 записей с одним server:port —
// это один лимит, и в профиле им делать нечего. Победитель группы — самый
// быстрый живой узел; если на пуле есть узел со статусом throttled или
// forbidden, пул выбрасывается целиком, потому что лимит общий, и
// «быстрый» узел того же пула сгорит вместе с ним.
//
// keep=0 отключает дедуп. keep<1 при включённом дедупе приводится к 1.
func dedupeByPool(nodes []model.Node, keep int) []model.Node {
	if keep < 0 {
		keep = 0
	}
	if keep == 0 {
		return nodes
	}

	poolOf := func(n model.Node) string {
		return probe.PoolKey(n.Server, n.Port)
	}
	statusOf := func(n model.Node) string {
		if n.Raw == nil {
			return ""
		}
		s, _ := n.Raw["status"].(string)
		return s
	}
	delayOf := func(n model.Node) float64 {
		if n.Raw == nil {
			return 1 << 30
		}
		if d, ok := n.Raw["delay_ms"].(float64); ok && d > 0 {
			return d
		}
		return 1 << 30
	}

	// Порядок первого появления пула сохраняется: профиль не должен
	// перетасовываться от прогона к прогону без причины.
	var order []string
	groups := map[string][]model.Node{}
	for _, n := range nodes {
		key := poolOf(n)
		if _, seen := groups[key]; !seen {
			order = append(order, key)
		}
		groups[key] = append(groups[key], n)
	}

	out := make([]model.Node, 0, len(order))
	for _, key := range order {
		members := groups[key]
		dirty := false
		for _, m := range members {
			switch statusOf(m) {
			case probe.StatusThrottled, probe.StatusForbidden:
				dirty = true
			}
		}
		if dirty {
			continue
		}

		var alive []model.Node
		for _, m := range members {
			if statusOf(m) == probe.StatusAlive {
				alive = append(alive, m)
			}
		}
		// Пул без статусов (старые результаты без поля status) не трогаем:
		// иначе экспорт после обновления начнёт молча терять узлы.
		if len(alive) == 0 && len(members) > 0 {
			out = append(out, members...)
			continue
		}
		sort.SliceStable(alive, func(i, j int) bool { return delayOf(alive[i]) < delayOf(alive[j]) })
		if len(alive) > keep {
			alive = alive[:keep]
		}
		out = append(out, alive...)
	}
	return out
}

// tcpReachable читает tcp.jsonl и возвращает узлы с открытым портом.
// Второе значение — был ли файл: без него отбор идёт только по HTTP-пробе.
func tcpReachable(workdir string) (map[string]bool, bool) {
	items, err := probe.ReadTCPResults(layout.TCPPath(workdir))
	if err != nil {
		return nil, false
	}
	live := make(map[string]bool, len(items))
	for _, r := range items {
		if r.OK {
			live[r.ID] = true
		}
	}
	return live, true
}

func cmdAll(ctx context.Context, args []string) error {
	// Аргументы фильтруются по шагу: у каждой подкоманды свой набор флагов,
	// и общий список уронил бы шаг на "flag provided but not defined".
	type step struct {
		name string
		fn   func(context.Context, []string) error
		own  []string // флаги, объявленные только этой подкомандой
	}
	steps := []step{
		{"fetch", cmdFetch, []string{"refresh", "attempts"}},
		{"parse", cmdParse, []string{"source"}},
		{"merge", cmdMerge, nil},
		{"ping", cmdPing, []string{"concurrency", "timeout"}},
		{"probe", cmdProbe, []string{"core", "url", "timeout", "concurrency"}},
		{"export", cmdExport, []string{"target", "keep-pools"}},
	}

	allStarted := time.Now()
	for i, st := range steps {
		// Прогресс в stderr: stdout каждого шага — данные, которые можно
		// перенаправить в файл, а «шаг 2 из 6» в тот же поток их испортил бы.
		fmt.Fprintf(os.Stderr, "[%d/%d] %s\n", i+1, len(steps), st.name)
		started := time.Now()
		if err := st.fn(ctx, filterArgs(args, st.own)); err != nil {
			return fmt.Errorf("step %s: %w", st.name, err)
		}
		fmt.Fprintf(os.Stderr, "[%d/%d] %s готово за %s\n",
			i+1, len(steps), st.name, time.Since(started).Round(time.Millisecond))
	}
	fmt.Fprintf(os.Stderr, "конвейер завершён за %s\n", time.Since(allStarted).Round(time.Millisecond))
	return nil
}

// filterArgs оставляет из аргументов только те, что понятны шагу.
//
// Общие флаги (-config, -workdir) и флаги самого шага проходят; чужие
// отбрасываются вместе со значением. Без этого шаг падает с
// «flag provided but not defined» на флаге соседней подкоманды.
func filterArgs(args []string, own []string) []string {
	allowed := map[string]bool{"config": true, "workdir": true}
	for _, name := range own {
		allowed[name] = true
	}

	var out []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		name := strings.TrimLeft(arg, "-")
		hasValue := strings.Contains(name, "=")
		key := name
		if idx := strings.Index(name, "="); idx >= 0 {
			key = name[:idx]
		}
		if !allowed[key] {
			continue
		}
		out = append(out, arg)
		// Флаг со отдельным значением: переносим значение вместе с ним.
		if !hasValue && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			out = append(out, args[i+1])
			i++
		}
	}
	return out
}
