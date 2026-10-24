// Package fetch скачивает подписки, не перезаписывая сырьё мусором.
package fetch

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
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
}

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
			if err == nil {
				return Result{ID: s.ID, Path: path, Size: int(info.Size()), SHA256: sum}
			}
		}
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: s.Insecure},
		Proxy:           http.ProxyFromEnvironment,
	}
	client := &http.Client{Timeout: timeout, Transport: transport}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return Result{ID: s.ID, Error: err}
	}
	if s.UA != "" {
		req.Header.Set("User-Agent", s.UA)
	}
	for k, v := range s.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return Result{ID: s.ID, Error: fmt.Errorf("fetch %s: %w", s.ID, err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Result{ID: s.ID, Error: fmt.Errorf("fetch %s: HTTP %d", s.ID, resp.StatusCode)}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{ID: s.ID, Error: fmt.Errorf("fetch %s: %w", s.ID, err)}
	}
	// Пустой ответ не перезаписывает рабочее сырьё: иначе один сбой сети
	// стирает данные, и следующий запуск молча работает с пустотой.
	if len(body) == 0 {
		return Result{ID: s.ID, Error: fmt.Errorf("fetch %s: empty body, raw file left untouched", s.ID)}
	}

	if err := os.WriteFile(path, body, 0o644); err != nil {
		return Result{ID: s.ID, Error: err}
	}
	sum := sha256.Sum256(body)
	return Result{ID: s.ID, Path: path, Size: len(body), SHA256: hex.EncodeToString(sum[:])}
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
