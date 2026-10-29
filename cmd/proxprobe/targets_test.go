package main

import (
	"reflect"
	"testing"
)

// TestSplitTargets закрывает панику из --target: пустой элемент в списке
// доезжал до emit.WriteAll, тот возвращал ошибку ВМЕСТЕ с уже записанными
// путями, и cmdExport падал на os.Stat пустого пути.
func TestSplitTargets(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"merged", []string{"merged"}},
		{"merged,sorted", []string{"merged", "sorted"}},
		{"merged,,sorted", []string{"merged", "sorted"}},
		{" merged , sorted ", []string{"merged", "sorted"}},
		{",", []string{"merged", "sorted"}},
		{"sorted,merged", []string{"sorted", "merged"}},
	}
	for _, tt := range tests {
		if got := splitTargets(tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("splitTargets(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

// TestHasFlag — пропуск шага probe включается только явным флагом: забытый
// --probe стоит 16 минут, а лишний прогон — тех же 16 минут, поэтому
// разбирается и «-probe», и «--probe=false».
func TestHasFlag(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{"--refresh"}, false},
		{[]string{"--probe"}, true},
		{[]string{"-probe"}, true},
		{[]string{"--probe=true"}, true},
		{[]string{"--probe=false"}, false},
		{[]string{"--concurrency", "24", "--probe"}, true},
		{[]string{"--probe-list"}, false},
	}
	for _, c := range cases {
		if got := hasFlag(c.args, "probe"); got != c.want {
			t.Errorf("hasFlag(%q) = %v, want %v", c.args, got, c.want)
		}
	}
}
