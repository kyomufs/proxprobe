package probe

import (
	"errors"
	"net/http"
	"testing"
)

func TestClassifyStatus(t *testing.T) {
	cases := map[int]string{
		http.StatusOK:                  StatusAlive,
		http.StatusNoContent:           StatusAlive,
		http.StatusTooManyRequests:     StatusThrottled,
		http.StatusForbidden:           StatusForbidden,
		http.StatusNotFound:            StatusDead,
		http.StatusInternalServerError: StatusDead,
	}
	for code, want := range cases {
		if got := classifyStatus(code); got != want {
			t.Errorf("classifyStatus(%d) = %q, want %q", code, got, want)
		}
	}
}

func TestStatusErrorKeepsBody(t *testing.T) {
	err := &statusError{code: http.StatusTooManyRequests, status: StatusThrottled,
		body: []byte(`{"error":"FreeUsageLimitError"}`)}
	var se *statusError
	if !errors.As(error(err), &se) {
		t.Fatalf("statusError does not unwrap via errors.As")
	}
	if se.status != StatusThrottled {
		t.Errorf("status lost: %q", se.status)
	}
	msg := err.Error()
	if msg == "" || !contains(msg, "FreeUsageLimitError") {
		t.Errorf("error message dropped the response body: %q", msg)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
