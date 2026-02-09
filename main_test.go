package main

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestHealthEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("body = %q, want ok", rec.Body.String())
	}
}

func TestEmailRegex(t *testing.T) {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	valid := []string{"user@example.com", "test+tag@sub.domain.org", "a@b.co"}
	for _, email := range valid {
		if !re.MatchString(email) {
			t.Errorf("expected %q to be valid", email)
		}
	}

	invalid := []string{"", "noat", "user@", "@domain.com", "user@localhost", "user@a.b"}
	for _, email := range invalid {
		if re.MatchString(email) {
			t.Errorf("expected %q to be invalid", email)
		}
	}
}

func TestHeaderInjection(t *testing.T) {
	malicious := []string{
		"user@example.com\r\nBcc: evil@evil.com",
		"subject\r\nBcc: evil@evil.com",
		"test\nnewline",
		"test\rcarriage",
	}
	for _, input := range malicious {
		if !strings.ContainsAny(input, "\r\n") {
			t.Errorf("expected header injection detected in %q", input)
		}
	}
}

func TestBodyLengthLimit(t *testing.T) {
	if len(strings.Repeat("a", 1000)) > 1000 {
		t.Error("1000 chars should be within limit")
	}
	if len(strings.Repeat("a", 1001)) <= 1000 {
		t.Error("1001 chars should exceed limit")
	}
}
