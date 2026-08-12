package oauth2server_test

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/apikey"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/oauth2server"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// countingListener counts accepted TCP connections. The assertion this test
// needs is "no outbound connection was made to a private address", which is a
// TRANSPORT fact — counting HTTP handler invocations would miss a connection
// that was opened and then failed a TLS handshake, i.e. exactly the pre-fix
// behaviour for an https:// issuer pointed at a plaintext victim.
type countingListener struct {
	net.Listener
	accepts *atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepts.Add(1)
	}
	return c, err
}

// victimService is a stand-in for something only the OP can reach — a metadata
// endpoint, an internal admin API, a database's HTTP interface. It counts every
// TCP connection that arrives so the test can assert on STATE (was it
// contacted?) rather than on what the handler said.
type victimService struct {
	srv     *httptest.Server
	accepts atomic.Int32
	addr    string
}

func newVictimService(t *testing.T) *victimService {
	t.Helper()
	v := &victimService{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": "http://unused.invalid/jwks"})
	}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	v.addr = ln.Addr().String()
	_ = srv.Listener.Close()
	srv.Listener = &countingListener{Listener: ln, accepts: &v.accepts}
	// The server's own error log would otherwise spew a TLS handshake error
	// for every https:// probe, which is noise, not signal.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.Start()
	v.srv = srv
	t.Cleanup(srv.Close)
	return v
}

// port returns the loopback port the victim listens on.
func (v *victimService) port(t *testing.T) string {
	t.Helper()
	_, port, err := net.SplitHostPort(v.addr)
	if err != nil {
		t.Fatalf("split victim addr: %v", err)
	}
	return port
}

// opServerForSSRF builds an OP with the handshake routes and an admin api key,
// with the private-network escape hatch under the test's control. This differs
// from opServerWithAdmin only in that AllowPrivateNetworkJWKSURI is a parameter
// — that helper hardcodes it to true so its loopback fixture IdP is reachable,
// which is precisely the setting under test here.
func opServerForSSRF(t *testing.T, allowPrivate bool) (*httptest.Server, string) {
	t.Helper()
	r := memrepo.New()
	cfg := yauth.NewDefaultConfig()
	cfg.AllowAdminMachineCallers = true
	now := time.Now().UTC()
	adminID := uuid.NewString()
	if _, err := r.CreateUser(t.Context(), domain.NewUser{ID: adminID, Email: "admin@op.test", Role: "admin", EmailVerified: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	gen, err := apikey.GenerateKey("yak")
	if err != nil {
		t.Fatal(err)
	}
	role := "admin"
	if err := r.CreateAPIKey(t.Context(), domain.NewAPIKey{ID: uuid.NewString(), UserID: &adminID, KeyPrefix: gen.Prefix, KeyHash: gen.Hash, Name: "test", Role: &role, CreatedByUserID: adminID, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	ya, err := yauth.New(r, cfg).
		WithJWTSecret([]byte("test-only-jwt-secret-please-change-32b")).
		WithPlugin(bearer.New(bearer.Config{})).
		WithPlugin(apikey.New(apikey.Config{})).
		WithPlugin(oauth2server.New(oauth2server.Config{
			Issuer:                     "http://op.test",
			BasePath:                   "/api/auth",
			DCREnabled:                 true,
			AllowPrivateNetworkJWKSURI: allowPrivate,
		})).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, gen.Plaintext
}

// signStatementForIssuer signs a federation_request naming an arbitrary `iss`.
// The signature is irrelevant to this test: the OP has to FETCH iss's discovery
// document before it can even look at the signature, which is the whole point.
func signStatementForIssuer(t *testing.T, iss string) string {
	t.Helper()
	peer := newPeerIssuer(t)
	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(iss).IssuedAt(now).Expiration(now.Add(10*time.Minute)).
		Claim("redirect_uris", []string{"https://app.test/cb"}).
		Claim("client_name", "Peer App").
		Claim("return_uri", "https://app.test/return").
		Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), peer.key))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

// TestFederateHandshake_NoRequestToPrivateNetwork is the SSRF regression.
//
// /federate/review and /federate/approve read `iss` off an UNVERIFIED JWT and
// GET iss + "/.well-known/openid-configuration", then the jwks_uri that
// document names. On the guided-handshake path there is no allow-list in front
// of that — the trust decision is the admin's click, which comes after. The
// client doing the fetching was plain http.DefaultTransport, so the OP would
// happily reach loopback and RFC 1918 addresses on the caller's behalf, while
// the private_key_jwt jwks_uri fetch twenty lines away had had an IP filter all
// along.
//
// The assertion is on state: the victim service must record ZERO requests. Not
// "the handler returned 400" — it returns 400 either way.
func TestFederateHandshake_NoRequestToPrivateNetwork(t *testing.T) {
	for _, path := range []string{"/api/auth/federate/review", "/api/auth/federate/approve"} {
		// "localhost" is a public-looking hostname that RESOLVES to 127.0.0.1,
		// so the https case exercises the post-DNS-resolution filter rather
		// than a string check on the URL.
		for _, scheme := range []string{"http", "https"} {
			t.Run(strings.TrimPrefix(path, "/api/auth/federate/")+"_"+scheme, func(t *testing.T) {
				victim := newVictimService(t)
				op, adminKey := opServerForSSRF(t, false)

				iss := scheme + "://localhost:" + victim.port(t)
				stmt := signStatementForIssuer(t, iss)

				code, out := postFed(t, op, path, adminKey, `{"federation_request":"`+stmt+`"}`)
				if code == http.StatusOK {
					t.Fatalf("%s: expected refusal, got 200 (%v)", path, out)
				}
				if got := victim.accepts.Load(); got != 0 {
					t.Fatalf("%s: SSRF — the OP opened %d connection(s) to %s on the caller's behalf", path, got, iss)
				}
			})
		}
	}
}

// TestFederateHandshake_ReachesAllowedIssuer is the control for the test above:
// with the documented development escape hatch on, the very same request DOES
// reach the loopback issuer. Without this, the refusal test could pass for a
// reason unrelated to the fix (a typo'd path, a 404, a rejected body) and
// nobody would know.
func TestFederateHandshake_ReachesAllowedIssuer(t *testing.T) {
	victim := newVictimService(t)
	op, adminKey := opServerForSSRF(t, true)

	iss := "http://localhost:" + victim.port(t)
	stmt := signStatementForIssuer(t, iss)

	// It still fails verification (the victim serves a bogus jwks_uri), but it
	// must have been CONTACTED — that is what makes the zero above meaningful.
	_, _ = postFed(t, op, "/api/auth/federate/review", adminKey, `{"federation_request":"`+stmt+`"}`)
	if got := victim.accepts.Load(); got == 0 {
		t.Fatalf("control: the OP never contacted %s, so the refusal test proves nothing", iss)
	}
}

// TestFederateHandshake_NoHostPortOracle pins the second half of the finding:
// the Go error text was returned to the caller through sanitizeErr, which
// strips control bytes and nothing else. "connection refused" vs "i/o timeout"
// vs "returned 404" is a working port scanner even when the request itself is
// blocked, so every failure that came from reaching out to the issuer now
// collapses to one fixed string and the detail goes to the log.
func TestFederateHandshake_NoHostPortOracle(t *testing.T) {
	victim := newVictimService(t)
	op, adminKey := opServerForSSRF(t, true) // fetch permitted; only the message is under test

	// A port nothing is listening on, so the dial fails in a way whose Go text
	// ("connection refused") would otherwise distinguish it from a live port.
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closed.Addr().(*net.TCPAddr).Port
	_ = closed.Close()

	openStmt := signStatementForIssuer(t, "http://localhost:"+victim.port(t))
	closedStmt := signStatementForIssuer(t, "http://127.0.0.1:"+itoa(closedPort))

	_, openOut := postFed(t, op, "/api/auth/federate/review", adminKey, `{"federation_request":"`+openStmt+`"}`)
	_, closedOut := postFed(t, op, "/api/auth/federate/review", adminKey, `{"federation_request":"`+closedStmt+`"}`)

	openMsg, _ := openOut["error"].(string)
	closedMsg, _ := closedOut["error"].(string)
	if openMsg != closedMsg {
		t.Fatalf("host/port oracle: an open port answers %q and a closed one %q — the caller can tell them apart", openMsg, closedMsg)
	}
	for _, leak := range []string{"connection refused", "dial tcp", "127.0.0.1", "no such host", "i/o timeout"} {
		if strings.Contains(strings.ToLower(closedMsg), leak) {
			t.Fatalf("error message leaks transport detail %q: %q", leak, closedMsg)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
