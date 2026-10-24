// Package probe проверяет живость узлов: сначала дешёвым TCP-коннектом,
// затем реальным HTTP-запросом через туннель ядра.
package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/kyomufs/proxprobe/internal/model"
)

// TCPResult — итог проверки TCP-коннекта до узла.
type TCPResult struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Server     string  `json:"server"`
	Port       int     `json:"port"`
	ResolvedIP string  `json:"resolved_ip,omitempty"`
	DNSMs      float64 `json:"dns_ms,omitempty"`
	DialMs     float64 `json:"dial_ms,omitempty"`
	OK         bool    `json:"ok"`
	Error      string  `json:"error,omitempty"`
}

// TCP проверяет доступность порта на всех узлах.
//
// Сначала отдельно замеряется резолв: у публичных подписок заметная часть
// узлов отваливается именно на нём, и в отчёте это должно быть видно, а не
// выглядеть как «порт закрыт».
func TCP(ctx context.Context, nodes []model.Node, concurrency int, timeout time.Duration) []TCPResult {
	if concurrency <= 0 {
		concurrency = 100
	}
	results := make([]TCPResult, len(nodes))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, n := range nodes {
		wg.Add(1)
		go func(i int, n model.Node) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			res := TCPResult{ID: n.ID, Name: n.Name, Server: n.Server, Port: n.Port}
			addr := net.JoinHostPort(n.Server, fmt.Sprint(n.Port))

			dnsStart := time.Now()
			ips, err := net.DefaultResolver.LookupHost(ctx, n.Server)
			res.DNSMs = msSince(dnsStart)
			if err != nil {
				res.Error = "dns: " + err.Error()
				results[i] = res
				return
			}
			if len(ips) > 0 {
				res.ResolvedIP = ips[0]
			}

			dialStart := time.Now()
			conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", addr)
			res.DialMs = msSince(dialStart)
			if err != nil {
				res.Error = "dial: " + err.Error()
				results[i] = res
				return
			}
			_ = conn.Close()
			res.OK = true
			results[i] = res
		}(i, n)
	}
	wg.Wait()
	return results
}

func msSince(t time.Time) float64 {
	return float64(time.Since(t).Microseconds()) / 1000.0
}

// WriteJSONL пишет результаты по строке на узел: формат читается глазами и
// не требует загрузки всего файла в память.
func WriteJSONL(path string, items []TCPResult) error {
	return writeJSONL(path, items)
}

func writeJSONL[T any](path string, items []T) error {
	f, err := createFile(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, item := range items {
		if err := enc.Encode(item); err != nil {
			return fmt.Errorf("probe: cannot encode result: %w", err)
		}
	}
	return nil
}

// Alive возвращает узлы, прошедшие TCP-проверку.
func Alive(nodes []model.Node, results []TCPResult) []model.Node {
	live := map[string]bool{}
	for _, r := range results {
		if r.OK {
			live[r.ID] = true
		}
	}
	out := make([]model.Node, 0, len(nodes))
	for _, n := range nodes {
		if live[n.ID] {
			out = append(out, n)
		}
	}
	return out
}

// Summarise считает сводку по результатам TCP-проверки.
func Summarise(results []TCPResult) (ok, dnsFail, dialFail int) {
	for _, r := range results {
		switch {
		case r.OK:
			ok++
		case r.Error != "" && len(r.Error) > 4 && r.Error[:4] == "dns:":
			dnsFail++
		default:
			dialFail++
		}
	}
	return ok, dnsFail, dialFail
}

// ReadResults читает результаты HTTP-пробы.
func ReadResults(path string) ([]Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Result
	dec := json.NewDecoder(f)
	for dec.More() {
		var r Result
		if err := dec.Decode(&r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// WriteResults пишет результаты HTTP-пробы по строке на узел.
func WriteResults(path string, items []Result) error {
	return writeJSONL(path, items)
}
