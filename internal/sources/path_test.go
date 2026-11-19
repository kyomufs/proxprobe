package sources

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile кладёт файл в отдельный каталог и возвращает путь к нему.
func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("cannot write %s: %v", path, err)
	}
	return path
}

func TestLoadReadsLocalPath(t *testing.T) {
	sub := writeFile(t, "config.yaml", "proxies: []\n")
	path := writeConfig(t, "sources:\n  - id: cache\n    path: "+sub+"\n")

	list, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("loaded %d sources, want 1", len(list))
	}
	if list[0].Path != sub {
		t.Errorf("path = %q, want %q", list[0].Path, sub)
	}
	if list[0].URL != "" {
		t.Errorf("local file kept a url: %q", list[0].URL)
	}
}

func TestLoadMakesLocalPathAbsolute(t *testing.T) {
	sub := writeFile(t, "sub.yaml", "proxies: []\n")
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot get working directory: %v", err)
	}
	rel, err := filepath.Rel(dir, sub)
	if err != nil {
		t.Fatalf("cannot build relative path: %v", err)
	}

	path := writeConfig(t, "sources:\n  - path: "+rel+"\n")
	list, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	// Относительный путь в конфиге считается от текущего каталога при чтении,
	// а дальше живёт абсолютным: иначе чтение зависит от того, откуда
	// запустили утилиту.
	if !filepath.IsAbs(list[0].Path) {
		t.Errorf("path %q is not absolute", list[0].Path)
	}
	if list[0].Path != sub {
		t.Errorf("path = %q, want %q", list[0].Path, sub)
	}
}

func TestLoadRejectsURLAndPathTogether(t *testing.T) {
	sub := writeFile(t, "sub.yaml", "proxies: []\n")
	path := writeConfig(t, "sources:\n  - url: https://example.org/sub\n    path: "+sub+"\n")
	if _, err := Load(path); err == nil {
		t.Fatal("one source cannot be both downloaded and read from disk")
	}
}

func TestLoadRejectsRequestFieldsOnLocalFile(t *testing.T) {
	cases := map[string]string{
		"ua":       "    ua: v2rayNG/1.9.16\n",
		"insecure": "    insecure: true\n",
		"headers":  "    headers:\n      x-hwid: device\n",
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			sub := writeFile(t, "sub.yaml", "proxies: []\n")
			path := writeConfig(t, "sources:\n  - path: "+sub+"\n"+extra)
			_, err := Load(path)
			if err == nil {
				t.Fatalf("%s on a local file must fail the load", name)
			}
			if !strings.Contains(err.Error(), "local file") {
				t.Errorf("error %q does not explain that the source is a file", err)
			}
		})
	}
}

func TestLoadRejectsMissingPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.yaml")
	path := writeConfig(t, "sources:\n  - path: "+missing+"\n")
	if _, err := Load(path); err == nil {
		t.Fatal("a path that does not exist must fail the load")
	}
}

func TestLoadRejectsDirectoryAsPath(t *testing.T) {
	path := writeConfig(t, "sources:\n  - path: "+t.TempDir()+"\n")
	if _, err := Load(path); err == nil {
		t.Fatal("a directory is not a subscription")
	}
}

func TestLoadCollapsesRepeatedPath(t *testing.T) {
	sub := writeFile(t, "sub.yaml", "proxies: []\n")
	path := writeConfig(t, "sources:\n  - path: "+sub+"\n  - path: "+sub+"\n")
	list, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("loaded %d sources, want 1", len(list))
	}
}

func TestNameOfLocalFile(t *testing.T) {
	cases := map[string]string{
		"/home/user/.local/share/com.follow.clash/config.yaml": "config",
		"/tmp/sub.yaml": "sub",
		"/tmp/clash":    "clash",
	}
	for path, want := range cases {
		if got := (Source{Path: path}).Name(); got != want {
			t.Errorf("Name(%q) = %q, want %q", path, got, want)
		}
	}
}
