package probe

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
			// Ошибки окружения (ядро не найдено, порты заняты чужим
			// процессом) — не «плохие узлы», а невозможность проверить
			// хоть один. Если их проглотить, прогон вернёт тысячу
			// batch-failed и выглядит как «все узлы мёртвы», хотя дело было
			// в занятом порту. Поэтому такие ошибки останавливают прогон.
			if isSetupError(err) {
				return nil, err
			}
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

// isSetupError сообщает, что ошибка относится к окружению прогона, а не к
// узлам: ядро недоступно или его порты заняты.
func isSetupError(err error) bool {
	msg := err.Error()
	for _, marker := range []string{
		"not found in PATH",
		"is busy",
		"cannot start",
		"cannot create run dir",
		"cannot render core config",
		"REST API did not come up",
		"no core-compatible nodes",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
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

	runDir, err := os.MkdirTemp("", "mihomo-probe-")
	if err != nil {
		return nil, fmt.Errorf("probe: cannot create run dir: %w", err)
	}
	defer os.RemoveAll(runDir)

	// Порты проверяются ДО старта. Если их держит чужое ядро (параллельный
	// прогон, живой клиент), наш процесс поднимется без инбаунда, а проба
	// будет мерить чужой конфиг: REST API чужого ядра ответит, mixed-port
	// чужого ядра примет запрос, и вердикты будут по чужим узлам.
	if err := portsFree(cfg); err != nil {
		return nil, err
	}

	configPath := filepath.Join(runDir, "config.yaml")
	coreNames, skipped, err := writeMihomoConfig(configPath, supported, cfg)
	if err != nil {
		return nil, err
	}
	// Узлы, которым ядро не может дать запись, не теряются: они попадают в
	// результат о непроверенными и видны в счётчиках отчёта.
	for _, n := range skipped {
		unsupported = append(unsupported, Result{
			ID: n.ID, Name: n.Name, Server: n.Server, Port: n.Port, Proto: n.Proto,
			OK: false, Error: "unsupported-by-core: core cannot represent this node",
		})
	}

	cmd := exec.CommandContext(ctx, corePath, "-d", runDir, "-f", configPath)
	// Вывод ядра идёт и в stderr (его видно в логе прогона), и в кольцевой
	// буфер: когда ядро падает на разборе конфига, причина остаётся в его
	// последних строках, а без буфера проба сообщает только «REST API did not
	// come up» — то есть не говорит ни что именно не так, ни в каком узле.
	coreLog := &tailBuffer{limit: 4096}
	cmd.Stdout = io.MultiWriter(os.Stderr, coreLog)
	cmd.Stderr = io.MultiWriter(os.Stderr, coreLog)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("probe: cannot start %s: %w", corePath, err)
	}
	defer stopProcess(cmd)

	base := fmt.Sprintf("http://127.0.0.1:%d", cfg.ControlPort)
	if err := waitForCore(ctx, base, 15*time.Second, coreLog); err != nil {
		return nil, err
	}

	// Порты должны принадлежать ИМЕННО этому ядру.
	//
	// Простой «кто-то слушает» не ловит случай: если порт уже занят чужим
	// ядром (параллельный прогон, живой клиент), чужой слушатель обнаружен,
	// а наш процесс пишет в лог "bind: address already in use" и остаётся
	// жив без инбаунда. Проба тогда мерит чужой конфиг и выдаёт вердикты по
	// чужим узлам. Поэтому порты занимаются ДО старта процесса.
	// Каждый узел идёт через селектор к ядру, который переключается на него
	// перед запросом. Полагаться на режим global нельзя, см. writeMihomoConfig.
	checked := sockProbe(ctx, supported, cfg, base, coreNames)
	return append(checked, unsupported...), nil
}

// portsFree проверяет, что mixed-port и external-controller свободны.
//
// Занятый порт означает, что поднимется не наш стек: ядро останется без
// инбаунда, а проба будет ходить через чужое ядро и мерить чужие узлы.
//
// Проверка идёт через Listen, а не через Dial: «connect не отдал
// ECONNREFUSED» — это не признак свободы порта, а признак того, что на нём
// кто-то есть. Свободный порт как раз отвечает отказом, поэтому прежняя
// проверка пропускала занятость насквозь (при медленном слушателе или
// SO_REUSEADDR) и проба мерила чужой конфиг.
//
// Освобождение портов берётся явно, ДО старта ядра. Это окно гонки: между
// Close и стартом ядра порт теоретически может занять кто-то ещё, но
// закрыть его полностью нельзя без передачи сокета ядру, а цена ошибки в
// этом окне — та же, что была раньше всегда.
func portsFree(cfg MihomoConfig) error {
	for _, p := range []struct {
		port int
		what string
	}{
		{cfg.MixedPort, "mixed-port"},
		{cfg.ControlPort, "external-controller"},
	} {
		addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(p.port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("probe: %s %d is busy: another core holds it, stop it or change the port", p.what, p.port)
		}
		_ = ln.Close()
	}
	return nil
}

// ProbeGroup — имя селектора, через который идут проверочные запросы.
// Конфиг ядра и код пробы ссылаются на него по имени, поэтому оно в одном
// месте.
const ProbeGroup = "PROBE"

// writeMihomoConfig генерирует тестовый конфиг и возвращает имена, под
// которыми узлы объявлены в нём, — по ID узла, — вместе со списком узлов,
// которым ядро не может дать запись.
//
// Имена узлов делаются уникальными: mihomo отвергает ВЕСЬ конфиг, если два
// прокси названы одинаково ("is the duplicate name"), а в публичных
// подписках повторяющиеся имена — норма (разные серверы с одинаковым
// названием локации). Дедуп по ID здесь не помогает: это разные серверы.
//
// Карта возвращается наружу, потому что проба переключает селектор по имени:
// повторить уникализацию на её стороне — значит разойтись с конфигом на
// первом же дубле, и тогда PUT уходит на ЧУЖОЙ узел, а вердикт и задержка
// приписываются не тому серверу.
func writeMihomoConfig(path string, nodes []model.Node, cfg MihomoConfig) (map[string]string, []model.Node, error) {
	doc := mihomoDoc{
		MixedPort: cfg.MixedPort,
		AllowLan:  false,
		// Режим rule с явным селектором, а НЕ global.
		//
		// global без proxy-groups бесполезен: ядро подставляет встроенный
		// селектор GLOBAL, у которого now=DIRECT, и весь проверочный трафик
		// уходит напрямую. Живость тогда не проверяется вовсе — мёртвый узел
		// 0.0.0.0:1 отвечал 2xx за 750 мс, а RTT мерил канал хоста. В логе
		// это видно как "using GLOBAL" вместо "dial PROBE".
		//
		// rule + MATCH,PROBE плохо тем, что при невыбранном узле срабатывает
		// первый прокси селектора. Поэтому селектор не создаётся неявно:
		// его наполняют только узлы текущего батча, а sockProbe переключает
		// его на каждый узел перед замером.
		Mode:               "rule",
		LogLevel:           "warning",
		ExternalController: fmt.Sprintf("127.0.0.1:%d", cfg.ControlPort),
		UnifiedDelay:       true,
		TCPConcurrent:      true,
		Proxies:            make([]map[string]any, 0, len(nodes)),
		Rules:              []string{"MATCH," + ProbeGroup},
	}

	used := map[string]int{}
	names := make([]string, 0, len(nodes))
	byID := make(map[string]string, len(nodes))
	var skipped []model.Node
	for _, n := range nodes {
		proxy, err := proxyForCore(n)
		if err != nil {
			// Узел, который ядру отдать нельзя, раньше исчезал молча: он не
			// попадал ни в конфиг, ни в отчёт. Теперь он возвращается
			// вызывающей стороне как непроверенный — иначе прогон выглядит
			// так, будто узел был проверен и оказался мёртв.
			skipped = append(skipped, n)
			continue
		}
		name := coreName(n.Name, used)
		proxy["name"] = name
		doc.Proxies = append(doc.Proxies, proxy)
		names = append(names, name)
		byID[n.ID] = name
	}

	// Группа обязана быть непустой: пустой proxies ядро не примет, а батч
	// без единого совместимого узла до сюда не доходит.
	if len(names) == 0 {
		return nil, skipped, fmt.Errorf("probe: no core-compatible nodes to build config")
	}
	doc.ProxyGroups = []map[string]any{{
		"name":    ProbeGroup,
		"type":    "select",
		"proxies": names,
	}}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, skipped, fmt.Errorf("probe: cannot render core config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, skipped, err
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return nil, skipped, err
	}
	return byID, skipped, nil
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
//
// Если ядро вышло раньше срока, ждать бессмысленно: причина уже лежит в его
// логе — именно она объясняет, какой узел не понравился ядру. Ошибка в этом
// случае несёт последнюю содержательную строку лога.
func waitForCore(ctx context.Context, base string, timeout time.Duration, coreLog *tailBuffer) error {
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
		if line := lastFatal(coreLog.String()); line != "" {
			return fmt.Errorf("probe: core exited: %s", line)
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("probe: core REST API did not come up within %s", timeout)
}

// lastFatal достаёт последнюю строку уровня fatal/error из лога ядра.
//
// Ядро пишет в лог всё, включая обычный ход загрузки, поэтому нужна именно
// строка отказа: она и есть причина, по которой конфиг не принят.
func lastFatal(log string) string {
	var found string
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, "level=fatal") || strings.Contains(line, "level=error") {
			found = strings.TrimSpace(line)
		}
	}
	return found
}

// tailBuffer хранит последние limit байт записанного.
//
// Нужен для лога ядра: держать его целиком нет смысла, а последние строки —
// это ровно то, что объясняет падение.
type tailBuffer struct {
	limit int
	buf   []byte
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.limit {
		b.buf = b.buf[len(b.buf)-b.limit:]
	}
	return len(p), nil
}

func (b *tailBuffer) String() string { return string(b.buf) }
