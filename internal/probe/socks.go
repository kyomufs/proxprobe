package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
// ошибку, хотя узел полностью работоспособен.
//
// Селектор ProbeGroup переключается на каждый узел перед замером: без
// переключения весь батч ушёл бы через первый прокси группы, и 499 из 500
// узлов получили бы чужую задержку и чужой вердикт.
func sockProbe(ctx context.Context, nodes []model.Node, cfg MihomoConfig, controlBase string, coreNames map[string]string) []Result {
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

			res := Result{
				ID: n.ID, Name: n.Name, Server: n.Server, Port: n.Port, Proto: n.Proto,
				Via: "socks", Pool: PoolKey(n.Server, n.Port),
			}
			coreName := coreNameFor(coreNames, n)

			// Селектор переключается и запрос идёт ПОД ОДНИМ замком, а не
			// под семафором параллельности. Семафор ограничивает число
			// одновременных воркеров, но не мешает соседу переключить
			// селектор между PUT и началом TLS-соединения: запрос тогда
			// уходит через чужой узел. На реальном прогоне это выглядело как
			// «все 32 узла проверялись через 217.60.59.1:2053» — первый,
			// кому повезло стартовать, утаскивал за собой весь батч.
			selectMu.Lock()
			selErr := selectNode(ctx, controlBase, ProbeGroup, coreName, cfg.Timeout)
			var delay float64
			var status string
			var err error
			if selErr == nil {
				delay, status, err = fetchThrough(ctx, dialer, n.Name, coreName, cfg)
			}
			selectMu.Unlock()

			switch {
			case selErr != nil:
				res.Status = StatusDead
				res.Error = "select node: " + selErr.Error()
			case err == nil:
				_ = status // классификация уже проверена в fetchThrough
				res.OK = true
				res.Status = StatusAlive
				res.DelayMs = delay
			default:
				// Узел жив, если цель ответила хоть чем-то: 429 и 403 —
				// это ответ, а не обрыв. В OK такие узлы не попадают
				// намеренно: OK значит «годен в профиль».
				var se *statusError
				if errors.As(err, &se) {
					res.Status = se.status
					res.DelayMs = delay
				} else {
					res.Status = StatusDead
				}
				res.Error = err.Error()
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

// selectMu сериализует «переключить селектор + сделать запрос»: селектор
// ProbeGroup один на батч, и параллельно переключать его нельзя.
var selectMu sync.Mutex

// coreNameFor возвращает имя узла, под которым он объявлен в конфиге ядра.
// Именно это имя селектор ProbeGroup принимает в PUT /proxies/PROBE.
//
// Имя берётся из карты, собранной вместе с конфигом: повторно уникализировать
// его здесь нельзя — расхождение с конфигом означает PUT на чужой узел.
func coreNameFor(coreNames map[string]string, n model.Node) string {
	if name, ok := coreNames[n.ID]; ok {
		return name
	}
	return n.Name
}

// selectNode переключает селектор ядра на узел с указанным именем.
//
// Ошибка здесь означает, что замер сделан бы не по тому узлу (или напрямую),
// поэтому узел помечается как непроверенный, а не как живой.
func selectNode(ctx context.Context, controlBase, group, name string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	payload, err := json.Marshal(map[string]string{"name": name})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		controlBase+"/proxies/"+url.PathEscape(group), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := controlClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("%s: HTTP %d %s", group, resp.StatusCode, bytes.TrimSpace(body))
	}
	return nil
}

// controlClient — клиент REST API ядра. Отдельный от http.DefaultClient:
// тот ходит через прокси из окружения, а API живёт на localhost.
var controlClient = &http.Client{Timeout: 10 * time.Second}

// fetchThrough выполняет HTTP-запрос через socks-диалайнер и возвращает
// задержку в миллисекундах и статус узла.
//
// Код ответа разбирается, а не сводится к «прошло/не прошло»: 429 от цели
// означает, что пул исчерпал квоту, и это не то же самое, что обрыв туннеля.
// Возвращается ошибка только когда запрос не состоялся вовсе.
func fetchThrough(ctx context.Context, dialer proxy.Dialer, name, coreName string, cfg MihomoConfig) (float64, string, error) {
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
		return 0, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	elapsed := float64(time.Since(start).Microseconds()) / 1000.0
	status := classifyStatus(resp.StatusCode)
	if status == StatusAlive {
		// Тело 2xx не нужно: важно, что ответ пришёл, а чтение тела
		// добавило бы к замеру чужую скорость канала цели.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return elapsed, status, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	return elapsed, status, &statusError{code: resp.StatusCode, status: status, body: bytes.TrimSpace(body)}
}

// statusError — ответ цели, при котором узел жив, но непригоден для неё.
// Отделён от транспортных ошибок: у 429 другой смысл и другое лечение.
type statusError struct {
	code   int
	status string
	body   []byte
}

func (e *statusError) Error() string {
	if len(e.body) > 0 {
		return fmt.Sprintf("%s: HTTP %d %s", e.status, e.code, e.body)
	}
	return fmt.Sprintf("%s: HTTP %d", e.status, e.code)
}

// classifyStatus переводит код ответа в статус узла.
//
// 429 и 403 не считаются мёртвыми: узел дошёл до цели и получил осмысленный
// ответ. Мёртвый узел — это обрыв, таймаут или иная транспортная ошибка.
func classifyStatus(code int) string {
	switch {
	case code >= 200 && code < 300:
		return StatusAlive
	case code == http.StatusTooManyRequests:
		return StatusThrottled
	case code == http.StatusForbidden:
		return StatusForbidden
	default:
		return StatusDead
	}
}
