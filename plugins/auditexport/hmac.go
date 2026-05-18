package auditexport

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// ComputeHMACSignature returns the hex-encoded HMAC-SHA256 of
// "<unixTS>.<body>" using secret as the key. The receiver MUST use the
// same input recipe — Stripe-style — so a captured signature cannot be
// replayed against a different body.
func ComputeHMACSignature(secret string, unixTS int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(unixTS, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyError surfaces the reason a signature was rejected. Consumers
// MUST treat anything other than nil as a hard failure — never log the
// error message into a publicly-accessible place since it can be used to
// fingerprint the signing key.
type VerifyError struct {
	Reason string
}

func (e *VerifyError) Error() string {
	return "auditexport: signature " + e.Reason
}

// Sentinel verify errors. Tests compare against these via errors.Is.
var (
	ErrMalformedHeader   = &VerifyError{Reason: "malformed header"}
	ErrStaleSignature    = &VerifyError{Reason: "outside accepted window"}
	ErrSignatureMismatch = &VerifyError{Reason: "does not match body"}
)

// VerifyHMACSignature is the receiver-side verification helper. Tests in
// downstream apps use this to validate the webhook contract.
//
// header is the raw X-Yauth-Signature header value, e.g.
// "t=1700000000,v1=<hex>". window is the max accepted timestamp drift
// from now; 5 minutes mirrors Stripe's webhook contract.
//
// Returns nil on success, or one of the sentinel VerifyError values
// wrapped under (errors.Is) so callers can branch on the failure mode
// without parsing strings.
func VerifyHMACSignature(secret string, header string, body []byte, now time.Time, window time.Duration) error {
	var (
		ts     int64
		tsSet  bool
		sigHex string
		sigSet bool
	)
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "t":
			n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				continue
			}
			ts = n
			tsSet = true
		case "v1":
			sigHex = strings.TrimSpace(v)
			sigSet = true
		}
	}
	if !tsSet || !sigSet {
		return ErrMalformedHeader
	}
	// Drift check.
	drift := now.Unix() - ts
	if drift < 0 {
		drift = -drift
	}
	if drift > int64(window.Seconds()) {
		return ErrStaleSignature
	}
	// Constant-time compare.
	expected := ComputeHMACSignature(secret, ts, body)
	if !hmac.Equal([]byte(expected), []byte(sigHex)) {
		return ErrSignatureMismatch
	}
	return nil
}

// Is implements errors.Is matching for VerifyError. Treats Reason as the
// identity so the sentinel values match instances constructed elsewhere
// with the same reason string.
func (e *VerifyError) Is(target error) bool {
	var ve *VerifyError
	if errors.As(target, &ve) {
		return ve.Reason == e.Reason
	}
	return false
}
