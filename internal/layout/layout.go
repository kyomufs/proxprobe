// Package layout держит имена артефактов прогона в одном месте.
//
// Раскладка по шагам конвейера, а не в одну кучу:
//
//	<workdir>/raw/<id>.raw        скачанное как есть + <id>.raw.meta.json
//	<workdir>/nodes/<id>.jsonl    разобранные узлы по источникам
//	<workdir>/merged.jsonl        после слияния
//	<workdir>/tcp.jsonl           после TCP-проверки
//	<workdir>/http.jsonl          после проверки через ядро
//	<workdir>/skip.log            строки, которые не удалось разобрать
//	<workdir>/profiles/*.yaml     готовые Clash-профили
//
// Имена вынесены сюда, потому что шаги читают файлы друг друга: опечатка в
// одном filepath.Join ломает конвейер не там, где сделана.
package layout

import "path/filepath"

// Имена подкаталогов и файлов внутри рабочего каталога.
const (
	RawDir      = "raw"
	NodesDir    = "nodes"
	ProfilesDir = "profiles"

	MergedFile = "merged.jsonl"
	TCPFile    = "tcp.jsonl"
	HTTPFile   = "http.jsonl"
	SkipFile   = "skip.log"
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
	return filepath.Join(workdir, MergedFile)
}

// TCPPath — результаты TCP-проверки.
func TCPPath(workdir string) string {
	return filepath.Join(workdir, TCPFile)
}

// HTTPPath — результаты проверки через ядро.
func HTTPPath(workdir string) string {
	return filepath.Join(workdir, HTTPFile)
}

// SkipPath — строки, которые не удалось разобрать.
func SkipPath(workdir string) string {
	return filepath.Join(workdir, SkipFile)
}

// ProfilesDirPath — каталог готовых профилей.
func ProfilesDirPath(workdir string) string {
	return filepath.Join(workdir, ProfilesDir)
}

// DirPath возвращает каталог, в котором шаг держит свои файлы. Нужен,
// чтобы каждый шаг создавал ровно то, что пишет.
func DirPath(workdir, dir string) string {
	return filepath.Join(workdir, dir)
}
