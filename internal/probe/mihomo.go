package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/kyomufs/proxprobe/internal/model"
)

// MihomoConfig — параметры запуска ядра для проверки.
type MihomoConfig struct {
	CorePath    string
	WorkDir     string
	MixedPort   int
	ControlPort int
	TestURL     string
	Timeout     time.Duration
	Concurrency int
	// Progress вызывается периодически с числом проверенных узлов батча.
	// Нужен, чтобы долгий прогон не выглядел зависанием.
	Progress func(done, total int)
}

// progress — колбэк текущего запуска.
var progress func(done, total int)

// Defaults возвращает параметры по умолчанию.
func Defaults() MihomoConfig {
	return MihomoConfig{
		MixedPort:   17890,
		ControlPort: 19090,
		TestURL:     "https://www.gstatic.com/generate_204",
		Timeout:     5 * time.Second,
		Concurrency: 8,
	}
}

// FindCore ищет бинарь ядра в PATH.
//
// Отдельная функция, потому что ошибка «ядро не найдено» должна
// объяснять, что включить, а не выглядеть как ошибка запуска процесса.
func FindCore(name string) (string, error) {
	if name == "" {
		name = "mihomo"
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf(
			"core %q not found in PATH: enable services.%s (NixOS) or install it manually", name, name)
	}
	return path, nil
}

// mihomoDoc — тестовый конфиг ядра: только прокси и API, без правил и DNS.
type mihomoDoc struct {
	MixedPort          int              `yaml:"mixed-port"`
	AllowLan           bool             `yaml:"allow-lan"`
	Mode               string           `yaml:"mode"`
	LogLevel           string           `yaml:"log-level"`
	ExternalController string           `yaml:"external-controller"`
	UnifiedDelay       bool             `yaml:"unified-delay"`
	TCPConcurrent      bool             `yaml:"tcp-concurrent"`
	Proxies            []map[string]any `yaml:"proxies"`
	ProxyGroups        []map[string]any `yaml:"proxy-groups"`
	Rules              []string         `yaml:"rules"`
}

// BatchSize — сколько узлов отдаётся ядру за один запуск.
//
// Ядро разбирает конфиг целиком и падает на первой неверной записи, теряя
// весь файл. Батч ограничивает цену такой ошибки: один плохой узел стоит
// BatchSize проверок, а не всех 8000.
const BatchSize = 500

// Mihomo прогоняет узлы через реальный туннель.
//
// Ядро поднимается ОДИН раз на батч: запускать процесс на каждый узел
// слишком дорого (на 400 узлах это 400 форков). Живость определяется
// встроенным в ядро замером задержки через REST API.
func Mihomo(ctx context.Context, nodes []model.Node, cfg MihomoConfig) ([]Result, error) {
	progress = cfg.Progress
	var all []Result
	var lastErr error

	for start := 0; start < len(nodes); start += BatchSize {
		end := start + BatchSize
		if end > len(nodes) {
			end = len(nodes)
		}
		if err := ctx.Err(); err != nil {
			return all, err
		}

		results, err := mihomoBatch(ctx, nodes[start:end], cfg)
		if err != nil {
			// Один батч не должен ронять прогон: помечаем его узлы как
			// непроверенные и идём дальше.
			lastErr = err
			for _, n := range nodes[start:end] {
				all = append(all, Result{
					ID: n.ID, Name: n.Name, Server: n.Server, Port: n.Port, Proto: n.Proto,
					Error: "batch-failed: " + err.Error(),
				})
			}
			continue
		}
		all = append(all, results...)
	}

	if len(all) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return all, nil
}

func mihomoBatch(ctx context.Context, nodes []model.Node, cfg MihomoConfig) ([]Result, error) {
	supported := make([]model.Node, 0, len(nodes))
	unsupported := make([]Result, 0)

	for _, n := range nodes {
		ok, reason := CoreCompatible(n)
		if ok {
			// Имя шифра приводится к нотации ядра здесь, а не в парсере:
			// каноническая модель хранит то, что было в источнике.
			if n.Proto == model.ProtoSS {
				n.Method = NormaliseCipher(n.Method)
			}
			supported = append(supported, n)
			continue
		}
		unsupported = append(unsupported, Result{
			ID: n.ID, Name: n.Name, Server: n.Server, Port: n.Port, Proto: n.Proto,
			OK: false, Error: "unsupported-by-core: " + reason,
		})
	}
	if len(supported) == 0 {
		return unsupported, nil
	}

	corePath, err := FindCore(cfg.CorePath)
	if err != nil {
		return nil, err
	}

	runDir, err := os.MkdirTemp(cfg.WorkDir, "mihomo-probe-")
	if err != nil {
		return nil, fmt.Errorf("probe: cannot create run dir: %w", err)
	}
	defer os.RemoveAll(runDir)

	configPath := filepath.Join(runDir, "config.yaml")
	if _, err := writeMihomoConfig(configPath, supported, cfg); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, corePath, "-d", runDir, "-f", configPath)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("probe: cannot start %s: %w", corePath, err)
	}
	defer stopProcess(cmd)

	base := fmt.Sprintf("http://127.0.0.1:%d", cfg.ControlPort)
	if err := waitForCore(ctx, base, 15*time.Second); err != nil {
		return nil, err
	}

	// Обход идёт socks-путём через mixed-port ядра. Режим global в конфиге
	// направляет весь трафик через проверяемый узел, поэтому отдельно
	// указывать имя узла не нужно.
	checked := sockProbe(ctx, supported, cfg)
	return append(checked, unsupported...), nil
}

// writeMihomoConfig генерирует тестовый конфиг.
//
// Имена узлов делаются уникальными: mihomo отвергает ВЕСЬ конфиг, если два
// прокси названы одинаково ("is the duplicate name"), а в публичных
// подписках повторяющиеся имена — норма (разные серверы с одинаковым
// названием локации). Дедуп по ID здесь не помогает: это разные серверы.
func writeMihomoConfig(path string, nodes []model.Node, cfg MihomoConfig) ([]string, error) {
	doc := mihomoDoc{
		MixedPort: cfg.MixedPort,
		AllowLan:  false,
		// Режим global обязателен: в режиме rule с MATCH,DIRECT весь трафик
		// mixed-port уходил бы НАПРЯМУЮ, минуя проверяемый узел, и проба
		// мерила бы собственный канал хоста. Проверено на живой машине:
		// с rule ядро писало "[TCP] ... match Match using DIRECT".
		Mode:               "global",
		LogLevel:           "warning",
		ExternalController: fmt.Sprintf("127.0.0.1:%d", cfg.ControlPort),
		UnifiedDelay:       true,
		TCPConcurrent:      true,
		Proxies:            make([]map[string]any, 0, len(nodes)),
		Rules:              []string{"MATCH,DIRECT"},
	}

	used := map[string]int{}
	names := make([]string, 0, len(nodes))
	for _, n := range nodes {
		proxy, err := proxyForCore(n)
		if err != nil {
			continue
		}
		name := coreName(n.Name, used)
		proxy["name"] = name
		doc.Proxies = append(doc.Proxies, proxy)
		names = append(names, name)
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("probe: cannot render core config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return names, os.WriteFile(path, buf.Bytes(), 0o600)
}

// coreName возвращает имя, под которым узел виден в REST API ядра.
// Должно совпадать с тем, что записано в конфиг.
func coreName(name string, seen map[string]int) string {
	count := seen[name]
	seen[name]++
	if count == 0 {
		return name
	}
	return fmt.Sprintf("%s #%d", name, count+1)
}

// proxyForCore собирает запись прокси для ядра.
//
// Имя узла сохраняется как есть, включая эмодзи: REST API принимает
// percent-encoded имена.
func proxyForCore(n model.Node) (map[string]any, error) {
	if raw, ok := n.Raw["clash"].(map[string]any); ok && len(raw) > 0 {
		proxy := map[string]any{}
		for k, v := range raw {
			proxy[k] = v
		}
		proxy["name"] = n.Name
		return proxy, nil
	}

	proxy := map[string]any{"name": n.Name, "server": n.Server, "port": n.Port}
	switch n.Proto {
	case model.ProtoVLESS:
		proxy["type"] = "vless"
		proxy["uuid"] = n.UUID
		if n.Flow != "" {
			proxy["flow"] = n.Flow
		}
	case model.ProtoVMess:
		proxy["type"] = "vmess"
		proxy["uuid"] = n.UUID
		proxy["alterId"] = 0
		proxy["cipher"] = orDefault(n.Method, "auto")
	case model.ProtoTrojan:
		proxy["type"] = "trojan"
		proxy["password"] = n.Password
	case model.ProtoSS:
		proxy["type"] = "ss"
		proxy["cipher"] = n.Method
		proxy["password"] = n.Password
	case model.ProtoSocks5:
		proxy["type"] = "socks5"
		if n.UUID != "" {
			proxy["username"] = n.UUID
			proxy["password"] = n.Password
		}
	case model.ProtoHysteria2:
		proxy["type"] = "hysteria2"
		proxy["password"] = n.Password
	case model.ProtoTuic:
		proxy["type"] = "tuic"
		proxy["uuid"] = n.UUID
		proxy["password"] = n.Password
	default:
		return nil, fmt.Errorf("probe: protocol %q is not supported by core", n.Proto)
	}

	if n.Network == model.NetWS {
		ws := map[string]any{"path": n.Path}
		if n.Host != "" {
			ws["headers"] = map[string]string{"Host": n.Host}
		}
		proxy["network"] = "ws"
		proxy["ws-opts"] = ws
	} else if n.Network == model.NetGRPC {
		proxy["network"] = "grpc"
		proxy["grpc-opts"] = map[string]any{"grpc-service-name": n.ServiceName}
	}

	switch n.Security {
	case model.SecTLS:
		proxy["tls"] = true
		if n.SNI != "" {
			proxy["servername"] = n.SNI
		}
	case model.SecReality:
		proxy["tls"] = true
		if n.SNI != "" {
			proxy["servername"] = n.SNI
		}
		reality := map[string]any{"public-key": n.PublicKey}
		if n.ShortID != "" {
			reality["short-id"] = n.ShortID
		}
		proxy["reality-opts"] = reality
		proxy["client-fingerprint"] = orDefault(n.Fingerprint, "chrome")
	}
	if len(n.ALPN) > 0 {
		proxy["alpn"] = n.ALPN
	}
	if n.Insecure {
		proxy["skip-cert-verify"] = true
	}
	return proxy, nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// stopProcess гасит ядро и не ждёт его бесконечно.
func stopProcess(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
	}
}

// waitForCore ждёт, пока REST API ядра ответит.
func waitForCore(ctx context.Context, base string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: time.Second}
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		resp, err := client.Get(base + "/version")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("probe: core REST API did not come up within %s", timeout)
}

// queryDelay спрашивает у ядра задержку конкретного узла.
func queryDelay(ctx context.Context, base, nodeName, testURL string, timeout time.Duration) (float64, error) {
	endpoint := fmt.Sprintf("%s/proxies/%s/delay?url=%s&timeout=%d",
		base, url.PathEscape(nodeName), url.QueryEscape(testURL), timeout.Milliseconds())

	ctx, cancel := context.WithTimeout(ctx, timeout+3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var payload struct {
		Delay   float64 `json:"delay"`
		Message string  `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return 0, fmt.Errorf("core returned unreadable response: %w", err)
	}
	if payload.Message != "" {
		return 0, fmt.Errorf("%s", payload.Message)
	}
	if payload.Delay <= 0 {
		return 0, fmt.Errorf("core reported zero delay")
	}
	return payload.Delay, nil
}
