package probe

import (
	"os"
	"path/filepath"
)

// createFile создаёт файл, попутно создавая родительский каталог.
func createFile(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	return os.Create(path)
}

// exists проверяет наличие файла.
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
