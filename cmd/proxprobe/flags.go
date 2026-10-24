package main

import "flag"

// commonFlags описывает флаги, которые есть у большинства команд.
type commonFlags struct {
	config  string
	workdir string
}

// bindCommon объявляет общие флаги в наборе команды.
//
// Раньше здесь был вызов Parse сразу после объявления двух флагов, и
// собственные флаги команды (-concurrency, -timeout, -refresh) в набор не
// попадали: flag.FlagSet разбирает только то, что уже объявлено. Теперь
// объявление и разбор разделены, и порядок вызовов в cmdX такой:
//
//	fs := flag.NewFlagSet("x", flag.ExitOnError)
//	c := bindCommon(fs)
//	myFlag := fs.Bool("my", false, "")
//	c.parse(fs, args)
type commonBinder struct {
	config  *string
	workdir *string
}

func bindCommon(fs *flag.FlagSet) commonBinder {
	return commonBinder{
		config:  fs.String("config", "sources.yaml", "path to sources.yaml"),
		workdir: fs.String("workdir", "out", "working directory"),
	}
}

// parse разбирает аргументы команды и возвращает значения общих флагов.
func (b commonBinder) parse(fs *flag.FlagSet, args []string) (commonFlags, error) {
	if err := fs.Parse(args); err != nil {
		return commonFlags{}, err
	}
	return commonFlags{config: *b.config, workdir: *b.workdir}, nil
}
