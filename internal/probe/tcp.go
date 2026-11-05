package probe

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/kyomufs/proxprobe/internal/model"
)

// TCPResult — подробности TCP-проверки: резолв и коннект.
type TCPResult struct {
	ID         string
	Name       string
	Server     string
	Port       int
	ResolvedIP string
	DNSMs      float64
	DialMs     float64
	OK         bool
	Error      string
}

// TCPCheck проверяет, что порт узла отвечает.
type TCPCheck struct {
	Workers int
	Timeout time.Duration
	DNS     []string
	// HostTUN — на машине TUN-клиент с fake-IP, TCP под ним не проверяем.
	HostTUN bool
}

func (c TCPCheck) Name() string { return "tcp" }

func (c TCPCheck) Run(ctx context.Context, nodes []model.Node) ([]model.Node, []Result, string, error) {
	if c.HostTUN {
		// Под fake-IP клиент принимает TCP локально и только потом идёт
		// вверх: коннект завершается за микросекунды при любом узле, и
		// проверка говорит «жив» про всё подряд. Врать в отчёте хуже,
		// чем пропустить шаг, поэтому TCP здесь не имеет смысла.
		return nodes, nil, "skipped: host TUN answers TCP locally, only http is real", nil
	}
	workers := c.Workers
	if workers <= 0 {
		workers = TCPWorkers
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = TCPTimeout
	}

	raw := TCP(ctx, nodes, workers, timeout, c.DNS)
	alive := make([]model.Node, 0, len(nodes))
	results := make([]Result, len(nodes))
	for i, n := range nodes {
		r := raw[i]
		results[i] = Result{
			ID: n.ID, Name: n.Name, Server: n.Server, Port: n.Port, Proto: n.Proto,
			OK: r.OK, DelayMs: r.DialMs, Error: r.Error,
		}
		if r.OK {
			alive = append(alive, n)
		}
	}
	return alive, results, "", nil
}

// TCP проверяет доступность порта на всех узлах.
//
// Резолв отделён от коннекта: у публичных подписок заметная часть узлов
// отваливается именно на нём, и в отчёте это должно быть видно, а не
// выглядеть как «порт закрыт».
func TCP(ctx context.Context, nodes []model.Node, concurrency int, timeout time.Duration, dns []string) []TCPResult {
	if concurrency <= 0 {
		concurrency = TCPWorkers
	}
	resolver := resolverFor(dns)
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

			dnsStart := time.Now()
			ips, err := resolver.LookupHost(ctx, n.Server)
			res.DNSMs = msSince(dnsStart)
			if err != nil {
				res.Error = "dns: " + err.Error()
				results[i] = res
				return
			}
			if len(ips) > 0 {
				res.ResolvedIP = ips[0]
			}
			// fake-IP — метка чужого TUN, а не адрес узла: коннект по нему
			// поднимет туннель машины, и «порт открыт» будет неправдой.
			if ip := net.ParseIP(res.ResolvedIP); ip != nil && fakeIPNet.Contains(ip) {
				res.Error = "dns: fake-ip " + res.ResolvedIP + " (TUN-клиент на машине, резолв мимо fake-ip)"
				results[i] = res
				return
			}

			// Коннект идёт по замеренному адресу, а не по имени: под
			// TUN-клиентом соединение по имени перехватывается хостом, и
			// замер в единицы миллисекунд принадлежит туннелю машины.
			dialAddr := net.JoinHostPort(n.Server, fmt.Sprint(n.Port))
			if ip := net.ParseIP(res.ResolvedIP); ip != nil {
				dialAddr = net.JoinHostPort(res.ResolvedIP, fmt.Sprint(n.Port))
			}

			dialStart := time.Now()
			conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", dialAddr)
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

// fakeIPNet — диапазон fake-IP у mihomo и его форков (FlClash, Clash Verge).
var fakeIPNet = &net.IPNet{IP: net.IPv4(198, 18, 0, 0), Mask: net.CIDRMask(15, 32)}

// resolverFor строит резолвер на явных серверах.
//
// Системный резолвер под TUN-клиентом отдаёт fake-IP, поэтому по умолчанию
// используются серверы из DefaultDNS. Пустой список оставляет системный:
// другого источника имён нет, и лучше показать его ошибку, чем не проверять
// узлы вовсе.
func resolverFor(servers []string) *net.Resolver {
	if len(servers) == 0 {
		return net.DefaultResolver
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var lastErr error
			for _, server := range servers {
				d := net.Dialer{Timeout: 3 * time.Second}
				conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
}

// DetectHostTUN сообщает, что на машине работает TUN-клиент с fake-IP.
//
// Признак — ответ системного резолвера из fake-IP диапазона. Проверять
// маршруты бессмысленно: клиент правит policy routing, и в main-таблице
// остаётся обычный default, по которому ничего не видно.
func DetectHostTUN() bool {
	ips, err := net.LookupHost("example.com")
	if err != nil {
		return false
	}
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed != nil && fakeIPNet.Contains(parsed) {
			return true
		}
	}
	return false
}
