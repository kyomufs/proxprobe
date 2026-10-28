// Package fetch скачивает подписки, не перезаписывая сырьё мусором.
package fetch

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/kyomufs/proxprobe/internal/sources"
)

// Result — итог скачивания одного источника.
type Result struct {
	ID     string
	Path   string
	Size   int
	SHA256 string
	Error  error
}

// Options — параметры скачивания.
type Options struct {
	RawDir  string
	Timeout time.Duration
	// Refresh перекачивает даже то, что уже лежит на диске.
	Refresh bool
	// Attempts — сколько раз пробовать один источник, прежде чем считать
	// его недоступным. 0 означает DefaultAttempts.
	//
	// Серверы подписок рвут TLS-handshake на части запросов: тот же URL
	// отвечает 200 и `unexpected eof while reading` через раз, и один обрыв
	// без повтора валит весь прогон на шаге fetch. Повтор здесь дешевле,
	// чем перезапуск конвейера вручную.
	Attempts int
}

// DefaultAttempts — сколько попыток делает fetch, если не сказано иное.
const DefaultAttempts = 3

// retryDelay — базовая пауза между попытками; растёт линейно.
var retryDelay = time.Second

// All скачивает все источники.
//
// Скачивание идёт последовательно: источников единицы, а параллельность
// здесь только мешает читать логи.
func All(ctx context.Context, list []sources.Source, opts Options) []Result {
	results := make([]Result, 0, len(list))
	for _, s := range list {
		results = append(results, One(ctx, s, opts))
	}
	return results
}

// One скачивает один источник.
func One(ctx context.Context, s sources.Source, opts Options) Result {
	if err := os.MkdirAll(opts.RawDir, 0o755); err != nil {
		return Result{ID: s.ID, Error: err}
	}
	path := filepath.Join(opts.RawDir, s.ID+".raw")

	if !opts.Refresh {
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			sum, err := fileSHA256(path)
			// Сырьё читается только если его происхождение известно. Файл без
			// боковой записи мог быть скачан с другими заголовками (x-hwid,
			// UA): сервер по ним отдаёт РАЗНЫЕ узлы, а прежний кэш молча
			// возвращал заглушку. Пропуск перезаписи здесь дешевле, чем
			// отладка конвейера на данных, к которым применён не тот запрос.
			if err == nil && metaMatches(metaPath(path), s) {
				return Result{ID: s.ID, Path: path, Size: int(info.Size()), SHA256: sum}
			}
		}
	}
	timeout := opts.Timeout

	if timeout == 0 {
		timeout = 60 * time.Second
	}
	attempts := opts.Attempts
	if attempts < 1 {
		attempts = DefaultAttempts
	}

	var (
		body    []byte
		lastErr error
	)
	for attempt := 1; attempt <= attempts; attempt++ {
		body, lastErr = download(ctx, s, timeout)
		if lastErr == nil {
			break
		}
		// Отменённый контекст повторять бессмысленно.
		if ctx.Err() != nil {
			break
		}
		if attempt < attempts {
			select {
			case <-ctx.Done():
			case <-time.After(retryDelay * time.Duration(attempt)):
			}
		}
	}
	if lastErr != nil {
		return Result{ID: s.ID, Error: lastErr}
	}
	// Пустой ответ не перезаписывает рабочее сырьё: иначе один сбой сети
	// стирает данные, и следующий запуск молча работает с пустотой.
	if len(body) == 0 {
		return Result{ID: s.ID, Error: fmt.Errorf("fetch %s: empty body, raw file left untouched", s.ID)}
	}

	if err := os.WriteFile(path, body, 0o644); err != nil {
		return Result{ID: s.ID, Error: err}
	}
	// Боковая запись пишется после сырья и без проверки ошибки в пути
	// возврата: если она не запишется, следующий запуск просто перекачает
	// файл заново — это дешевле, чем оставить кэш без опознавания.
	_ = writeMeta(metaPath(path), s)

	sum := sha256.Sum256(body)
	return Result{ID: s.ID, Path: path, Size: len(body), SHA256: hex.EncodeToString(sum[:])}
}

// download делает одну попытку скачивания и возвращает тело ответа.
//
// Транспорт создаётся на каждую попытку: после оборванного TLS-handshake
// переиспользовать пул соединений бессмысленно, а свежий клиент снимает
// вопрос «сломался сервер или залип коннект».
func download(ctx context.Context, s sources.Source, timeout time.Duration) ([]byte, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: s.Insecure},
		Proxy:           http.ProxyFromEnvironment,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{Timeout: timeout, Transport: transport}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return nil, err
	}
	if s.UA != "" {
		req.Header.Set("User-Agent", s.UA)
	}
	for k, v := range s.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", s.ID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", s.ID, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", s.ID, err)
	}
	return body, nil
}

// metaPath — боковая запись о том, каким запросом получено сырьё.
func metaPath(rawPath string) string { return rawPath + ".meta.json" }

// fetchMeta — то, от чего зависит содержимое ответа. URL и заголовки
// сравниваются целиком: подписки меняют выдачу по любому из них, а разница
// между 34 реальными узлами и заглушкой 0.0.0.0:1 в них не видна.
type fetchMeta struct {
	URL      string            `json:"url"`
	UA       string            `json:"ua"`
	Headers  map[string]string `json:"headers"`
	Insecure bool              `json:"insecure"`
}

func metaFor(s sources.Source) fetchMeta {
	return fetchMeta{URL: s.URL, UA: s.UA, Headers: s.Headers, Insecure: s.Insecure}
}

func writeMeta(path string, s sources.Source) error {
	body, err := json.MarshalIndent(metaFor(s), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o644)
}

// metaMatches сообщает, скачано ли сырьё тем же запросом, что описан сейчас.
// Отсутствие или порча записи — повод перекачать.
func metaMatches(path string, s sources.Source) bool {
	body, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var got fetchMeta
	if err := json.Unmarshal(body, &got); err != nil {
		return false
	}
	return reflect.DeepEqual(got, metaFor(s))
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
