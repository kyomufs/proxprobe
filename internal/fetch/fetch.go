// Package fetch скачивает подписки в память.
//
// Файлы на диск не пишутся: узлы разбираются сразу, а исходные тела
// сохраняются только по явному --dump-raw для разбора неудачного формата.
package fetch

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kyomufs/proxprobe/internal/sources"
)

const (
	// DefaultUA — клиент, под который источники отдают список share-ссылок.
	DefaultUA = "v2rayNG/1.9.16"
	// DefaultAttempts — сколько раз пробовать один источник.
	DefaultAttempts = 3
	// DefaultTimeout — таймаут одной попытки.
	DefaultTimeout = 20 * time.Second
	// maxBody ограничивает подписку: 32 МиБ с запасом покрывают крупные
	// сборники, а всё большее — уже не подписка.
	maxBody = 32 << 20
	// parallel — сколько источников качать одновременно.
	parallel = 8
)

// Options — параметры скачивания.
type Options struct {
	Attempts int
	Timeout  time.Duration
	DumpDir  string
}

// Result — итог по одному источнику. Body заполняется и при ошибке дампа.
type Result struct {
	Index   int
	Source  sources.Source
	Body    []byte
	Err     error
	DumpErr error
}

// All качает все источники параллельно, сохраняя порядок конфига.
//
// Ошибка одного источника не мешает остальным: подписки независимы, и
// потерять из-за одной упавшей все остальные было бы хуже.
func All(ctx context.Context, list []sources.Source, opts Options) []Result {
	if opts.Attempts <= 0 {
		opts.Attempts = DefaultAttempts
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}

	out := make([]Result, len(list))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup

	for i, src := range list {
		wg.Add(1)
		go func(i int, src sources.Source) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			body, err := one(ctx, src, opts)
			res := Result{Index: i, Source: src, Body: body, Err: err}
			if err == nil && opts.DumpDir != "" {
				res.DumpErr = dump(opts.DumpDir, i+1, src, body)
			}
			out[i] = res
		}(i, src)
	}
	wg.Wait()
	return out
}

// one скачивает источник с повторами.
func one(ctx context.Context, src sources.Source, opts Options) ([]byte, error) {
	client := &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			// Проверка сертификата подписки отключается только по просьбе
			// из конфига: сам источник может стоять на самоподписанном
			// сертификате.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: src.Insecure},
		},
	}

	var lastErr error
	for n := 1; n <= opts.Attempts; n++ {
		if n > 1 {
			pause := time.Duration(n-1) * 500 * time.Millisecond
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(pause):
			}
		}
		body, err := fetchOnce(ctx, client, src)
		if err == nil {
			return body, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func fetchOnce(ctx context.Context, client *http.Client, src sources.Source) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return nil, err
	}
	ua := strings.TrimSpace(src.UA)
	if ua == "" {
		ua = DefaultUA
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Тело ошибки не читается: у прокси-провайдеров там бывает HTML на
		// мегабайт, а код ответа уже объясняет причину.
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("response is larger than %d MiB", maxBody>>20)
	}
	return body, nil
}

// unsafeName оставляет в имени файла только безопасные символы.
var unsafeName = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// dump сохраняет исходное тело источника для разбора вручную.
func dump(dir string, index int, src sources.Source, body []byte) error {
	name := unsafeName.ReplaceAllString(src.Name(), "_")
	if name == "" {
		name = "source"
	}
	path := filepath.Join(dir, fmt.Sprintf("%02d-%s.txt", index, name))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o644)
}
