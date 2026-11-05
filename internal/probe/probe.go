// Package probe проверяет узлы: дешёвым TCP-коннектом и реальным запросом
// через ядро mihomo.
//
// Проверки независимы и включаются по одной через --check. HTTP-проверка по
// умолчанию идёт через REST API ядра: у ядра свой DNS, и замер не зависит от
// TUN-клиента на машине.
package probe

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kyomufs/proxprobe/internal/model"
)

// Параметры проверок. Вынесены в константы: CLI их не настраивает, а разные
// значения в разных местах — это разные вердикты по одному узлу.
const (
	// TCPWorkers — сколько коннектов открывается одновременно. Коннект
	// дешёвый, поэтому параллельность высокая.
	TCPWorkers = 200
	// TCPTimeout — таймаут резолва и коннекта.
	TCPTimeout = 2 * time.Second
	// HTTPJobs — сколько узлов ядро проверяет одновременно.
	HTTPJobs = 16
	// HTTPTimeout — таймаут одного запроса через узел.
	HTTPTimeout = 5 * time.Second
)

// Result — итог одной проверки узла.
type Result struct {
	ID      string
	Name    string
	Server  string
	Port    int
	Proto   string
	OK      bool
	DelayMs float64
	Error   string
}

// Check — одна проверка списка узлов.
//
// Возвращаются выжившие узлы и результаты по всем, кого проверка получила:
// отчёт должен объяснять и отсев, а не только успех.
type Check interface {
	Name() string
	// Run возвращает выжившие узлы, результаты по всем проверенным и
	// пояснение, если проверку пришлось пропустить.
	Run(ctx context.Context, nodes []model.Node) (alive []model.Node, results []Result, note string, err error)
}

// Options — параметры, общие для набора проверок.
type Options struct {
	CorePath string
	Jobs     int
	Timeout  time.Duration
	DNS      []string
	TestURL  string
	Progress func(done, total int)
	// HostTUN — на машине работает TUN-клиент с fake-IP: TCP-проверка
	// под ним бессмысленна, см. TCPCheck.Run.
	HostTUN bool
}

// ParseChecks разбирает --check в список проверок.
//
// Порядок фиксирован: tcp идёт первым, потому что отсеивает мёртвые адреса
// до запуска ядра. Пустая строка и none значат «проверок нет».
func ParseChecks(spec string, opts Options) ([]Check, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "none" {
		return nil, nil
	}

	set := map[string]bool{}
	for _, part := range strings.Split(spec, ",") {
		switch name := strings.TrimSpace(part); name {
		case "":
			continue
		case "none":
			return nil, fmt.Errorf("--check none must be used alone")
		case "tcp", "http":
			set[name] = true
		default:
			return nil, fmt.Errorf("unknown check %q (supported: none, tcp, http)", name)
		}
	}

	var checks []Check
	if set["tcp"] {
		checks = append(checks, TCPCheck{HostTUN: opts.HostTUN})
	}
	if set["http"] {
		cfg := Defaults()
		if opts.CorePath != "" {
			cfg.CorePath = opts.CorePath
		}
		if opts.Jobs > 0 {
			cfg.Concurrency = opts.Jobs
		}
		if opts.Timeout > 0 {
			cfg.Timeout = opts.Timeout
		}
		if len(opts.DNS) > 0 {
			cfg.DNS = opts.DNS
		}
		if opts.TestURL != "" {
			cfg.TestURL = opts.TestURL
		}
		cfg.Progress = opts.Progress
		checks = append(checks, HTTPCheck{cfg: cfg})
	}
	return checks, nil
}
