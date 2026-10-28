package layout

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSkipPathIsUnderNodesDir держит skip.log там, где его пишет шаг parse.
// Раньше файл лежал в probe/, хотя шаг probe его не касается, и раскладка
// «по шагам» переставала что-либо значить.
func TestSkipPathIsUnderNodesDir(t *testing.T) {
	want := filepath.Join("out", NodesDir, SkipFile)
	if got := SkipPath("out"); got != want {
		t.Errorf("SkipPath = %q, want %q", got, want)
	}
	if filepath.Dir(SkipPath("out")) != DirPath("out", NodesDir) {
		t.Error("skip.log lives outside the nodes directory")
	}
}

func TestEnsurePathCreatesParent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, NodesDir, "nested", SkipFile)
	if err := EnsurePath(path); err != nil {
		t.Fatalf("EnsurePath returned error: %v", err)
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil || !info.IsDir() {
		t.Fatalf("parent directory was not created: %v", err)
	}
}

// TestArtifactsStayUnderWorkdir — раскладка не должна выводить артефакты за
// пределы рабочего каталога: прогон обязан быть переносимым каталогом.
func TestArtifactsStayUnderWorkdir(t *testing.T) {
	workdir := "/tmp/run"
	paths := map[string]string{
		"raw":    RawPath(workdir, "src"),
		"nodes":  NodesPath(workdir, "src"),
		"merged": MergedPath(workdir),
		"tcp":    TCPPath(workdir),
		"http":   HTTPPath(workdir),
		"skip":   SkipPath(workdir),
		"clash":  ClashDirPath(workdir),
	}
	for name, p := range paths {
		if rel, err := filepath.Rel(workdir, p); err != nil || rel == ".." || filepath.IsAbs(rel) {
			t.Errorf("%s path %q escapes the workdir", name, p)
		}
	}
}
