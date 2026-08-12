package oauth2server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// trustedStatement is the verified result of a DCR software_statement.
type trustedStatement struct {
	Issuer           string
	RedirectURIs     []string
	ClientName       string
	Scope            string
	InitiateLoginURI string // optional: the RP's SP-initiated launch URL
	ReturnURI        string // guided handshake: where the IdP redirects after approval
}

// errIssuerFetch marks every failure that came from TALKING to the issuer
// (DNS, dial, TLS, status code, body decode) as opposed to parsing or verifying
// the statement itself. Handlers collapse it to one fixed message: the Go error
// text distinguishes "connection refused" from "i/o timeout" from "returned
// 401", which is exactly the discrimination that turns a blind SSRF into a
// host/port scanner for the caller.
var errIssuerFetch = errors.New("could not retrieve the issuer's signing keys")

// trustedIssuerClient is the HTTP client used to fetch a software_statement
// issuer's discovery document and JWKS.
//
// The URL it is pointed at comes from the `iss` of an UNVERIFIED JWT — on the
// guided-handshake path (verifyStatementSignature) there is no allow-list in
// front of it at all, because the trust decision there is the admin's click,
// which happens AFTER this fetch. That makes the fetch itself the SSRF
// primitive, so it gets the same post-DNS-resolution IP filter that the
// private_key_jwt jwks_uri fetch has had (safeDialContext, which resolves and
// checks every A record before dialling and so is DNS-rebinding-proof).
//
// Redirects are capped at 3 rather than the default 10; each hop is re-dialled
// through the same guard, so the cap is about bounding work, not about safety.
func (p *oauth2Plugin) trustedIssuerClient() *http.Client {
	if p.cfg.DCRTrustedIssuerHTTPClient != nil {
		return p.cfg.DCRTrustedIssuerHTTPClient
	}
	// otelhttp so the W3C traceparent propagates to the peer issuer when we fetch
	// its discovery + JWKS to verify a software_statement.
	base := http.DefaultTransport
	if !p.cfg.AllowPrivateNetworkJWKSURI {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.DialContext = safeDialContext(&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		})
		base = t
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: otelhttp.NewTransport(base),
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

// issuerFetchAllowed rejects an issuer URL before any packet leaves the
// process. The IP filter in safeDialContext handles where the request GOES;
// this handles what it can be at all — an `iss` of "file:///etc/passwd" or
// "gopher://…" never reaches a dialer, and plaintext http is refused outside
// the development escape hatch that already exists for loopback JWKS.
func (p *oauth2Plugin) issuerFetchAllowed(issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("software_statement issuer is not a valid URL")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !p.cfg.AllowPrivateNetworkJWKSURI {
			return fmt.Errorf("software_statement issuer must be an https URL")
		}
	default:
		return fmt.Errorf("software_statement issuer must be an https URL")
	}
	if u.Host == "" {
		return fmt.Errorf("software_statement issuer must be an https URL")
	}
	return nil
}

// statementErrMessage renders a software_statement verification failure for the
// wire. Parse/verify failures describe themselves — they are about the caller's
// own JWT and help an integrator. Anything that came from reaching out to the
// issuer collapses to errIssuerFetch's fixed text: the underlying Go error
// distinguishes refused/timeout/404/TLS-mismatch per host and port, which is a
// working network scanner for whoever supplies the `iss`. The detail is logged
// for the operator instead.
func statementErrMessage(ctx context.Context, log *slog.Logger, err error) string {
	if errors.Is(err, errIssuerFetch) {
		if log != nil {
			log.WarnContext(ctx, "oauth2server: software_statement issuer fetch failed", "err", err)
		}
		return errIssuerFetch.Error()
	}
	return sanitizeErr(err)
}

// verifySoftwareStatement validates a DCR software_statement (RFC 7591): it reads
// the unverified `iss`, requires it to be allow-listed, fetches that issuer's
// JWKS via its OIDC discovery, and verifies the JWT signature + standard claims.
// On success the registrant has proven control of a trusted issuer — no admin
// credential or shared secret required. Returns the attested client metadata.
func (p *oauth2Plugin) verifySoftwareStatement(ctx context.Context, jws string) (*trustedStatement, error) {
	if len(p.cfg.DCRTrustedIssuers) == 0 {
		return nil, errors.New("trusted-issuer DCR is disabled")
	}
	unverified, err := jwt.Parse([]byte(jws), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("software_statement parse: %w", err)
	}
	unverifiedIss, _ := unverified.Issuer()
	if iss := strings.TrimSpace(unverifiedIss); iss == "" || !issuerAllowed(iss, p.cfg.DCRTrustedIssuers) {
		return nil, fmt.Errorf("software_statement issuer %q is not trusted", iss)
	}
	return p.verifyStatementSignature(ctx, jws)
}

// verifyStatementSignature verifies a software_statement's signature against its
// OWN issuer's published JWKS (read from the unverified iss → discovery → jwks),
// WITHOUT requiring the issuer to be pre-allow-listed. Use it where a human
// approval (not a static allow-list) is the trust gate — e.g. the guided
// federation handshake. Returns the attested client metadata.
func (p *oauth2Plugin) verifyStatementSignature(ctx context.Context, jws string) (*trustedStatement, error) {
	unverified, err := jwt.Parse([]byte(jws), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("software_statement parse: %w", err)
	}
	rawIss, _ := unverified.Issuer()
	iss := strings.TrimSpace(rawIss)
	if iss == "" {
		return nil, errors.New("software_statement has no issuer")
	}
	if err := p.issuerFetchAllowed(iss); err != nil {
		return nil, err
	}

	// Resolve the issuer's JWKS via its discovery document. Every failure from
	// here to the end of the JWKS fetch is wrapped in errIssuerFetch so callers
	// cannot read the peer's dial/status detail back off the response — see
	// errIssuerFetch.
	hc := p.trustedIssuerClient()
	jwksURI, err := fetchIssuerJWKSURI(ctx, hc, iss)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errIssuerFetch, err)
	}
	// jwks_uri is the issuer's own claim about where its keys live and is
	// fetched next, so it is a second SSRF hop and gets the same pre-flight.
	if err := p.issuerFetchAllowed(jwksURI); err != nil {
		return nil, fmt.Errorf("%w: %w", errIssuerFetch, err)
	}
	set, err := jwk.Fetch(ctx, jwksURI, jwk.WithHTTPClient(hc))
	if err != nil {
		return nil, fmt.Errorf("%w: fetch trusted issuer JWKS: %w", errIssuerFetch, err)
	}

	// 3. Verify signature + standard claims (exp, iss) against that key set.
	tok, err := jwt.Parse([]byte(jws),
		jwt.WithKeySet(set),
		jwt.WithValidate(true),
		jwt.WithIssuer(iss),
		jwt.WithAcceptableSkew(60*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("software_statement verification failed: %w", err)
	}

	tokIss, _ := tok.Issuer()
	out := &trustedStatement{Issuer: tokIss}
	if v, ok := claim(tok, "redirect_uris"); ok {
		out.RedirectURIs = toStringSlice(v)
	}
	out.ClientName = stringClaim(tok, "client_name")
	out.Scope = stringClaim(tok, "scope")
	out.InitiateLoginURI = stringClaim(tok, "initiate_login_uri")
	out.ReturnURI = stringClaim(tok, "return_uri")
	return out, nil
}

// claim reads an arbitrary claim from tok, reporting whether it was present.
//
// jwx v3 replaced v2's `(value, ok)` accessor with `Get(key, dst) error`,
// which INVERTS the signal: absence is now an error rather than a false
// second return. Getting this backwards would compile cleanly and silently
// attest claims a software_statement never made — so the polarity is
// centralised here rather than repeated at each call site.
func claim(tok jwt.Token, key string) (any, bool) {
	var v any
	if err := tok.Get(key, &v); err != nil {
		return nil, false
	}
	return v, true
}

// stringClaim returns a string claim, or "" when the claim is absent or is
// not a string. This matches the v2 form exactly: the outer presence check
// and the inner type assertion both had to pass before the field was set,
// so a present-but-non-string claim leaves the field at its zero value.
func stringClaim(tok jwt.Token, key string) string {
	v, ok := claim(tok, key)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func issuerAllowed(iss string, allow []string) bool {
	norm := strings.TrimRight(iss, "/")
	for _, a := range allow {
		if strings.TrimRight(strings.TrimSpace(a), "/") == norm {
			return true
		}
	}
	return false
}

func fetchIssuerJWKSURI(ctx context.Context, hc *http.Client, issuer string) (string, error) {
	url := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	res, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch trusted issuer discovery: %w", err)
	}
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("trusted issuer discovery returned %d", res.StatusCode)
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("decode trusted issuer discovery: %w", err)
	}
	if doc.JWKSURI == "" {
		return "", errors.New("trusted issuer advertises no jwks_uri")
	}
	return doc.JWKSURI, nil
}

func toStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
