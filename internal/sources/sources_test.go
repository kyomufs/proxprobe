package sources

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sources.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("cannot write config: %v", err)
	}
	return path
}

func TestLoadReadsURLUAAndInsecure(t *testing.T) {
	path := writeConfig(t, `
sources:
  - url: https://pro1link.ru/sub?token=x
    ua: v2rayNG/1.9.16
    insecure: true
  - url: https://example.org/list.txt
`)

	list, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("loaded %d sources, want 2", len(list))
	}
	if list[0].UA != "v2rayNG/1.9.16" || !list[0].Insecure {
		t.Errorf("first source lost ua/insecure: %+v", list[0])
	}
	if list[1].UA != "" || list[1].Insecure {
		t.Errorf("second source got defaults it did not declare: %+v", list[1])
	}
}

func TestLoadCollapsesDuplicateURLs(t *testing.T) {
	path := writeConfig(t, `
sources:
  - url: https://example.org/sub
  - url: https://example.org/sub
`)
	list, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("loaded %d sources, want 1: the same address is one subscription", len(list))
	}
}

func TestLoadRejectsEntryWithoutURL(t *testing.T) {
	path := writeConfig(t, `
sources:
  - ua: v2rayNG/1.9.16
`)
	if _, err := Load(path); err == nil {
		t.Fatal("entry without url must fail the load")
	}
}

func TestLoadRejectsNonHTTPURL(t *testing.T) {
	path := writeConfig(t, `
sources:
  - url: file:///etc/passwd
`)
	if _, err := Load(path); err == nil {
		t.Fatal("only http(s) urls are readable by the fetcher")
	}
}

func TestNameIsHostWithoutWWW(t *testing.T) {
	cases := map[string]string{
		"https://www.example.org/sub": "example.org",
		"https://pro1link.ru/sub":     "pro1link.ru",
	}
	for raw, want := range cases {
		if got := (Source{URL: raw}).Name(); got != want {
			t.Errorf("Name(%q) = %q, want %q", raw, got, want)
		}
	}
}
