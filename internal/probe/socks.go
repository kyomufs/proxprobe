package probe

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"

	"github.com/kyomufs/proxprobe/internal/model"
)

// sockProbe проверяет узлы HTTP-запросом через socks-инбаунд ядра.
//
// Почему не встроенный в ядро замер задержки (GET /proxies/{n}/delay):
// на машине с уже поднятым VPN системный резолвер отдаёт fake-IP
// (198.18.0.0/16) — так работает fake-ip режим боевого клиента. Тестовое
// ядро резолвит имя узла в этот же fake-адрес, уходит на него и получает
// ошибку, хотя узел полностью работоспособен. Проверено на этой машине:
// /delay отвечает "An error occurred in the delay test" при живом flclash,
// тогда как прямой socks-запрос к тому же узлу отдаёт 204 за 0.12 с.
//
// Socks-путь свободен от этой проблемы: имя узла уходит в ядро внутри
// SOCKS-запроса, а не через локальный резолвер.
func sockProbe(ctx context.Context, nodes []model.Node, cfg MihomoConfig) []Result {
	results := make([]Result, len(nodes))
	workers := cfg.Concurrency
	if workers <= 0 {
		workers = 16
	}

	var done atomic.Int64
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(cfg.MixedPort))
	dialer, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		for i, n := range nodes {
			results[i] = Result{ID: n.ID, Name: n.Name, Error: "socks dialer: " + err.Error()}
		}
		return results
	}

	for i, n := range nodes {
		wg.Add(1)
		go func(i int, n model.Node) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			delay, err := fetchThrough(ctx, dialer, n.Name, coreNameFor(cfg, n), cfg)
			res := Result{ID: n.ID, Name: n.Name, Server: n.Server, Port: n.Port, Proto: n.Proto, Via: "socks"}
			if err != nil {
				res.Error = err.Error()
			} else {
				res.OK = true
				res.DelayMs = delay
			}
			results[i] = res
			done.Add(1)
		}(i, n)
	}

	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if progress != nil {
					progress(int(done.Load()), len(nodes))
				}
			}
		}
	}()

	wg.Wait()
	close(stop)
	return results
}

// coreNameFor возвращает имя узла, под которым он объявлен в конфиге ядра.
// Для socks-пути имя не используется — запрос идёт через mixed-port, где
// активен режим global — но параметр оставлен ради единой сигнатуры.
func coreNameFor(_ MihomoConfig, n model.Node) string { return n.Name }

// fetchThrough выполняет HTTP-запрос через socks-диалайнер и возвращает
// задержку в миллисекундах.
func fetchThrough(ctx context.Context, dialer proxy.Dialer, name, coreName string, cfg MihomoConfig) (float64, error) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			type ctxDialer interface {
				DialContext(ctx context.Context, network, address string) (net.Conn, error)
			}
			if d, ok := dialer.(ctxDialer); ok {
				return d.DialContext(ctx, network, address)
			}
			return dialer.Dial(network, address)
		},
		// Проверка сертификата отключена осознанно: через чужой узел идёт
		// только запрос к эталонному URL, секретов в нём нет, а разбор
		// цепочки на чужой стороне добавляет недостоверные отказы.
		TLSClientConfig:   insecureTLS(),
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: transport, Timeout: cfg.Timeout}
	defer transport.CloseIdleConnections()

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.TestURL, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	elapsed := float64(time.Since(start).Microseconds()) / 1000.0
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return 0, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return elapsed, nil
}
