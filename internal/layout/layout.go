// Package layout держит имена артефактов прогона в одном месте.
//
// Раскладка по шагам конвейера, а не в одну кучу:
//
//	<workdir>/raw/<id>.raw          скачанное как есть + <id>.raw.meta.json
//	<workdir>/nodes/<id>.jsonl      разобранные узлы по источникам
//	<workdir>/nodes/skip.log        строки, которые не удалось разобрать
//	<workdir>/probe/merged.jsonl    после слияния
//	<workdir>/probe/tcp.jsonl       после TCP-проверки
//	<workdir>/probe/http.jsonl      после проверки через ядро
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
//
// Имена Clash-профилей здесь не объявлены: их держит emit — тот пакет, что
// их и пишет. Дублировать их тут означало бы второй источник правды, который
// разъезжается при переименовании.
const (
	RawDir   = "raw"
	NodesDir = "nodes"
	ProbeDir = "probe"
	ClashDir = "clash"

	MergedFile = "merged.jsonl"
	TCPFile    = "tcp.jsonl"
	HTTPFile   = "http.jsonl"
	SkipFile   = "skip.log"
)

// RawPath — сырьё одного источника.
func RawPath(workdir, id string) string {
	return filepath.Join(workdir, RawDir, id+".raw")
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
//
// Лежит в nodes/, а не в probe/: файл пишет шаг parse, и держать его в
// каталоге шага, который его не касается, значит путать «где артефакт шага»
// с «кто его создал» — ровно то, от чего раскладка по шагам и защищает.
func SkipPath(workdir string) string {
	return filepath.Join(workdir, NodesDir, SkipFile)
}

// ClashDirPath — каталог готовых Clash-профилей.
func ClashDirPath(workdir string) string {
	return filepath.Join(workdir, ClashDir)
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
