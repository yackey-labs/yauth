package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// req builds a request with the given peer and headers.
func req(remoteAddr string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// TestClientIP_ProxiedRequestIsOneValue is the regression guard for the
// finding: sessions were WRITTEN with RequestIP (X-Forwarded-For first) and
// COMPARED against clientIP (RemoteAddr only), so behind any reverse proxy
// the two never matched and every request looked like a hijack.
//
// Before the fix this failed on the very first assertion: write="203.0.113.9",
// compare="10.0.0.5".
func TestClientIP_ProxiedRequestIsOneValue(t *testing.T) {
	// A request as an ingress/nginx on private space presents it.
	r := req("10.0.0.5:41234", map[string]string{"X-Forwarded-For": "203.0.113.9"})

	write := RequestIP(r)
	if write == nil {
		t.Fatal("RequestIP returned nil for a proxied request")
	}
	compare := TrustedProxies{}.ClientIP(r)

	if *write != compare {
		t.Fatalf("write/compare disagree: session stored %q but the binding check sees %q", *write, compare)
	}
	if *write != "203.0.113.9" {
		t.Fatalf("client IP = %q; want the real client 203.0.113.9", *write)
	}
}

// TestClientIP_ForgedXFFFromUntrustedPeerIsIgnored covers the second half of
// the finding: X-Forwarded-For used to be believed from ANY peer, so a client
// talking straight to the listener could name whatever address it liked and
// that address landed in every audit row, session and AuthEvent, and flowed
// out to SIEMs via auditexport.
//
// Before the fix this returned the forged 1.2.3.4.
func TestClientIP_ForgedXFFFromUntrustedPeerIsIgnored(t *testing.T) {
	// A public peer: nothing in front of us, so nothing may speak for it.
	r := req("198.51.100.7:52000", map[string]string{
		"X-Forwarded-For": "1.2.3.4",
		"X-Real-IP":       "5.6.7.8",
	})

	got := TrustedProxies{}.ClientIP(r)
	if got != "198.51.100.7" {
		t.Fatalf("client IP = %q; want the peer 198.51.100.7 — a forwarding header from an untrusted peer must not be believed", got)
	}
	if ip := RequestIP(r); ip == nil || *ip != "198.51.100.7" {
		t.Fatalf("RequestIP = %v; want 198.51.100.7", ip)
	}
}

func TestClientIP_DefaultPolicy(t *testing.T) {
	cases := []struct {
		name    string
		peer    string
		headers map[string]string
		want    string
	}{
		{
			name: "loopback peer is trusted (local nginx, sidecar, tests)",
			peer: "127.0.0.1:9000",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.9",
			},
			want: "203.0.113.9",
		},
		{
			name:    "no forwarding header falls back to the peer",
			peer:    "203.0.113.9:1000",
			headers: nil,
			want:    "203.0.113.9",
		},
		{
			name: "rightmost untrusted hop wins over an appended forgery",
			// The client sent "1.2.3.4"; the ingress appended the address
			// it actually saw. The real client is the rightmost entry
			// that is not itself a proxy.
			peer: "10.0.0.5:41234",
			headers: map[string]string{
				"X-Forwarded-For": "1.2.3.4, 198.51.100.20",
			},
			want: "198.51.100.20",
		},
		{
			name: "all-private chain resolves to the leftmost (LAN client)",
			peer: "10.0.0.5:41234",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.20, 10.0.0.9",
			},
			want: "192.168.1.20",
		},
		{
			name: "junk entries are skipped, never returned",
			peer: "10.0.0.5:41234",
			headers: map[string]string{
				"X-Forwarded-For": "not-an-ip, 203.0.113.9, <script>",
			},
			want: "203.0.113.9",
		},
		{
			name: "X-Real-IP is honoured from a trusted peer",
			peer: "10.0.0.5:41234",
			headers: map[string]string{
				"X-Real-IP": "203.0.113.9",
			},
			want: "203.0.113.9",
		},
		{
			name: "entries carrying a port are still parsed",
			peer: "10.0.0.5:41234",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.9:5555",
			},
			want: "203.0.113.9",
		},
		{
			name: "IPv6 peer is canonical and unbracketed",
			peer: "[2001:db8::1]:443",
			want: "2001:db8::1",
		},
		{
			name: "IPv6 loopback peer is trusted",
			peer: "[::1]:443",
			headers: map[string]string{
				"X-Forwarded-For": "2001:db8::99",
			},
			want: "2001:db8::99",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := (TrustedProxies{}).ClientIP(req(tc.peer, tc.headers)); got != tc.want {
				t.Fatalf("ClientIP = %q; want %q", got, tc.want)
			}
		})
	}
}

func TestParseTrustedProxies(t *testing.T) {
	xff := map[string]string{"X-Forwarded-For": "203.0.113.9"}

	t.Run("all restores unconditional trust", func(t *testing.T) {
		tp, err := ParseTrustedProxies([]string{TrustedProxiesAll})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		// Even from a public peer, which the default would refuse.
		if got := tp.ClientIP(req("198.51.100.7:1", xff)); got != "203.0.113.9" {
			t.Fatalf("ClientIP = %q; want 203.0.113.9", got)
		}
	})

	t.Run("none never believes a header", func(t *testing.T) {
		tp, err := ParseTrustedProxies([]string{TrustedProxiesNone})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got := tp.ClientIP(req("127.0.0.1:1", xff)); got != "127.0.0.1" {
			t.Fatalf("ClientIP = %q; want the peer 127.0.0.1", got)
		}
	})

	t.Run("an explicit list replaces the private default", func(t *testing.T) {
		tp, err := ParseTrustedProxies([]string{"198.51.100.7"})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		// The named public LB is now trusted...
		if got := tp.ClientIP(req("198.51.100.7:1", xff)); got != "203.0.113.9" {
			t.Fatalf("ClientIP = %q; want 203.0.113.9", got)
		}
		// ...and private space no longer is, because the operator said
		// exactly who the proxies are.
		if got := tp.ClientIP(req("10.0.0.5:1", xff)); got != "10.0.0.5" {
			t.Fatalf("ClientIP = %q; want the peer 10.0.0.5", got)
		}
	})

	t.Run("private can be extended with a CDN range", func(t *testing.T) {
		tp, err := ParseTrustedProxies([]string{TrustedProxiesPrivate, "173.245.48.0/20"})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got := tp.ClientIP(req("173.245.48.9:1", xff)); got != "203.0.113.9" {
			t.Fatalf("CDN edge: ClientIP = %q; want 203.0.113.9", got)
		}
		if got := tp.ClientIP(req("10.0.0.5:1", xff)); got != "203.0.113.9" {
			t.Fatalf("private peer: ClientIP = %q; want 203.0.113.9", got)
		}
	})

	t.Run("an empty list is the private default", func(t *testing.T) {
		tp, err := ParseTrustedProxies(nil)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got := tp.ClientIP(req("10.0.0.5:1", xff)); got != "203.0.113.9" {
			t.Fatalf("ClientIP = %q; want 203.0.113.9", got)
		}
	})

	t.Run("a malformed entry is an error, not a silent default", func(t *testing.T) {
		if _, err := ParseTrustedProxies([]string{"10.0.0.0/8", "nonsense"}); err == nil {
			t.Fatal("expected an error for a malformed trusted_proxies entry")
		}
	})
}

func TestTrustedProxiesMiddleware_AppliesPolicyToRequestIP(t *testing.T) {
	// "none" installed on the context must beat the built-in default, so a
	// deployment that turns forwarding off really gets the peer.
	tp, err := ParseTrustedProxies([]string{TrustedProxiesNone})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	var got string
	h := TrustedProxiesMiddleware(tp)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if ip := RequestIP(r); ip != nil {
			got = *ip
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), req("127.0.0.1:1", map[string]string{"X-Forwarded-For": "203.0.113.9"}))

	if got != "127.0.0.1" {
		t.Fatalf("RequestIP under the none policy = %q; want 127.0.0.1", got)
	}
}
