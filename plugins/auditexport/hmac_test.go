package auditexport

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestHMACSignature_Deterministic(t *testing.T) {
	a := ComputeHMACSignature("k", 1000, []byte("body"))
	b := ComputeHMACSignature("k", 1000, []byte("body"))
	if a != b {
		t.Errorf("signature not deterministic: %s vs %s", a, b)
	}
}

func TestHMACSignature_ChangesWithTimestamp(t *testing.T) {
	a := ComputeHMACSignature("k", 1000, []byte("body"))
	b := ComputeHMACSignature("k", 1001, []byte("body"))
	if a == b {
		t.Error("signature should change with timestamp")
	}
}

func TestVerifyHMAC_Accepts(t *testing.T) {
	body := []byte("hello")
	ts := int64(1_700_000_000)
	sig := ComputeHMACSignature("k", ts, body)
	header := fmt.Sprintf("t=%d,v1=%s", ts, sig)
	if err := VerifyHMACSignature("k", header, body, time.Unix(ts, 0), 60*time.Second); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
}

func TestVerifyHMAC_RejectsBadSignature(t *testing.T) {
	body := []byte("hello")
	ts := int64(1_700_000_000)
	header := fmt.Sprintf("t=%d,v1=%s", ts, strings.Repeat("00", 32))
	err := VerifyHMACSignature("k", header, body, time.Unix(ts, 0), 60*time.Second)
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch, got %v", err)
	}
}

func TestVerifyHMAC_RejectsStale(t *testing.T) {
	body := []byte("hello")
	ts := int64(1_700_000_000)
	sig := ComputeHMACSignature("k", ts, body)
	header := fmt.Sprintf("t=%d,v1=%s", ts, sig)
	// 1000s drift > 300s window
	now := time.Unix(ts+1000, 0)
	err := VerifyHMACSignature("k", header, body, now, 300*time.Second)
	if !errors.Is(err, ErrStaleSignature) {
		t.Errorf("expected ErrStaleSignature, got %v", err)
	}
}

func TestVerifyHMAC_MalformedHeader(t *testing.T) {
	err := VerifyHMACSignature("k", "no-equal-sign", []byte("x"), time.Now(), 60*time.Second)
	if !errors.Is(err, ErrMalformedHeader) {
		t.Errorf("expected ErrMalformedHeader, got %v", err)
	}
}
