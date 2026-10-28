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
