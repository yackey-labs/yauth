package auth

import (
	"net/http/httptest"
	"testing"
)

func TestResolveCookieDomain_Literal(t *testing.T) {
	r := httptest.NewRequest("GET", "http://app.example.com/", nil)
	if got := ResolveCookieDomain(".example.com", r); got != ".example.com" {
		t.Fatalf("literal: got %q", got)
	}
	if got := ResolveCookieDomain("", r); got != "" {
		t.Fatalf("empty: got %q", got)
	}
}

func TestResolveCookieDomain_Auto(t *testing.T) {
	r := httptest.NewRequest("GET", "http://tenant1.app.example.com/x", nil)
	if got := ResolveCookieDomain("auto", r); got != "tenant1.app.example.com" {
		t.Fatalf("auto: got %q want %q", got, "tenant1.app.example.com")
	}
}

func TestResolveCookieDomain_AutoStripsPort(t *testing.T) {
	r := httptest.NewRequest("GET", "http://app.example.com:8080/x", nil)
	if got := ResolveCookieDomain("auto", r); got != "app.example.com" {
		t.Fatalf("port-strip: got %q", got)
	}
}

func TestResolveCookieDomain_AutoCaseInsensitive(t *testing.T) {
	r := httptest.NewRequest("GET", "http://h.example.com/", nil)
	if got := ResolveCookieDomain("Auto", r); got != "h.example.com" {
		t.Fatalf("Auto: got %q", got)
	}
	if got := ResolveCookieDomain("AUTO", r); got != "h.example.com" {
		t.Fatalf("AUTO: got %q", got)
	}
}

func TestResolveCookieDomain_AutoNoHost(t *testing.T) {
	r := httptest.NewRequest("GET", "http://h.example.com/", nil)
	r.Host = ""
	if got := ResolveCookieDomain("auto", r); got != "" {
		t.Fatalf("empty host: got %q", got)
	}
	if got := ResolveCookieDomain("auto", nil); got != "" {
		t.Fatalf("nil request: got %q", got)
	}
}
