// Package layout держит имена артефактов прогона в одном месте.
//
// Раскладка по шагам конвейера, а не в одну кучу:
//
//	<workdir>/raw/<id>.raw          скачанное как есть + <id>.raw.meta.json
//	<workdir>/nodes/<id>.jsonl      разобранные узлы по источникам
//	<workdir>/probe/merged.jsonl    после слияния
//	<workdir>/probe/tcp.jsonl       после TCP-проверки
//	<workdir>/probe/http.jsonl      после проверки через ядро
//	<workdir>/probe/skip.log        строки, которые не удалось разобрать
//	<workdir>/clash/merged.yaml     все узлы, Clash-профиль
//	<workdir>/clash/sorted.yaml     живые, по возрастанию задержки
//
// Имена вынесены сюда, потому что шаги читают файлы друг друга: опечатка в
// одном filepath.Join ломает конвейер не там, где сделана.
package layout

import (
	"os"
	"path/filepath"
)

// Имена подкаталогов и файлов внутри рабочего каталога.
const (
	RawDir   = "raw"
	NodesDir = "nodes"
	ProbeDir = "probe"
	ClashDir = "clash"

	MergedFile = "merged.jsonl"
	TCPFile    = "tcp.jsonl"
	HTTPFile   = "http.jsonl"
	SkipFile   = "skip.log"

	MergedClash = "merged.yaml"
	SortedClash = "sorted.yaml"
)

// RawPath — сырьё одного источника.
func RawPath(workdir, id string) string {
	return filepath.Join(workdir, RawDir, id+".raw")
}

// RawMetaPath — боковая запись с параметрами запроса, которым получено
// сырьё. Без неё кэш не отличает подписку с нужным User-Agent от заглушки,
// полученной тем же URL с другим заголовком.
func RawMetaPath(workdir, id string) string {
	return RawPath(workdir, id) + ".meta.json"
}

// NodesPath — разобранные узлы одного источника.
func NodesPath(workdir, id string) string {
	return filepath.Join(workdir, NodesDir, id+".jsonl")
}

// MergedPath — результат слияния источников.
func MergedPath(workdir string) string {
	return filepath.Join(workdir, ProbeDir, MergedFile)
}

// TCPPath — результаты TCP-проверки.
func TCPPath(workdir string) string {
	return filepath.Join(workdir, ProbeDir, TCPFile)
}

// HTTPPath — результаты проверки через ядро.
func HTTPPath(workdir string) string {
	return filepath.Join(workdir, ProbeDir, HTTPFile)
}

// SkipPath — строки, которые не удалось разобрать.
func SkipPath(workdir string) string {
	return filepath.Join(workdir, ProbeDir, SkipFile)
}

// ClashDirPath — каталог готовых Clash-профилей.
func ClashDirPath(workdir string) string {
	return filepath.Join(workdir, ClashDir)
}

// MergedClashPath — Clash-профиль со всеми узлами.
func MergedClashPath(workdir string) string {
	return filepath.Join(workdir, ClashDir, MergedClash)
}

// SortedClashPath — Clash-профиль только из живых узлов.
func SortedClashPath(workdir string) string {
	return filepath.Join(workdir, ClashDir, SortedClash)
}

// DirPath возвращает каталог, в котором шаг держит свои файлы. Нужен,
// чтобы каждый шаг создавал ровно то, что пишет.
func DirPath(workdir, dir string) string {
	return filepath.Join(workdir, dir)
}

// EnsurePath создаёт родительский каталог для файла шага.
//
// Каталог артефакта теперь не верхнего уровня (probe/, clash/), и шаг,
// который просто открывает файл на запись, падал бы с ENOENT, если его
// вызвали не после предыдущего шага. Каждый шаг создаёт свою папку сам.
func EnsurePath(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0o755)
}
