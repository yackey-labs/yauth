package ssosaml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugin"
)

// logoutRequestXML is the minimal subset of a SAML 2.0 <LogoutRequest> we read.
type logoutRequestXML struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`
	ID      string   `xml:"ID,attr"`
	Issuer  string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameID  string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
}

// handleSamlSLO receives an IdP-initiated SAML Single Logout request over the
// HTTP-Redirect binding, verifies its signature against the IdP certificate,
// and terminates the matching local sessions server-side — making IdP-side
// offboarding propagate to this SAML SP.
//
// Security: the LogoutRequest signature is REQUIRED and verified against the
// connection's configured IdP cert (SAML Binding §3.4.4.1 redirect-binding
// signature over the raw query). An unsigned or badly-signed request is
// rejected, closing the "anyone can force-logout any NameID" hole the previous
// MVP stub documented. Only the HTTP-Redirect binding is accepted.
func (p *ssoSAMLPlugin) handleSamlSLO(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Redirect binding carries params in the query (GET) or, for some IdPs,
		// a urlencoded body (POST). Use the raw source so we can reconstruct the
		// exact signed octet string.
		rawSource := r.URL.RawQuery
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			rawSource = string(body)
		}
		raw := parseRawQuery(rawSource)

		samlReq := urlDecode(raw["SAMLRequest"])
		sigAlg := urlDecode(raw["SigAlg"])
		signature := urlDecode(raw["Signature"])
		relayState := urlDecode(raw["RelayState"])
		if samlReq == "" || sigAlg == "" || signature == "" {
			writeSLOError(w, "missing SAMLRequest/SigAlg/Signature (signed HTTP-Redirect binding required)")
			return
		}

		xmlBytes, err := inflateSAML(samlReq)
		if err != nil {
			writeSLOError(w, "could not decode SAMLRequest")
			return
		}
		var lr logoutRequestXML
		if err := xml.Unmarshal(xmlBytes, &lr); err != nil || strings.TrimSpace(lr.NameID) == "" {
			writeSLOError(w, "malformed LogoutRequest")
			return
		}
		reqIssuer := strings.TrimSpace(lr.Issuer)
		nameID := strings.TrimSpace(lr.NameID)

		// Find the SAML connection whose IdP entity id matches the request.
		ctx := r.Context()
		conns, err := host.Repo().ListAllSsoConnections(ctx)
		if err != nil {
			writeSLOError(w, "internal error")
			return
		}
		var cfg *SamlConnectionConfig
		for _, conn := range conns {
			if conn.Kind != domain.ConnectionKindSamlSP || conn.Status != domain.ConnectionStatusActive {
				continue
			}
			c, err := unmarshalSamlConfig(p.cfg.EncryptionKey, conn.Config)
			if err != nil {
				continue
			}
			if IssuerKeyFromEntityID(c.IdpEntityID) == IssuerKeyFromEntityID(reqIssuer) {
				cc := c
				cfg = &cc
				break
			}
		}
		if cfg == nil {
			writeSLOError(w, "no SAML connection matches the request issuer")
			return
		}

		// Verify the redirect-binding signature against the IdP cert.
		cert, err := parsePEMCert(cfg.IdpX509Cert)
		if err != nil {
			writeSLOError(w, "idp cert unreadable")
			return
		}
		if err := verifyRedirectSignature(rawSource, sigAlg, signature, cert); err != nil {
			writeSLOError(w, "LogoutRequest signature invalid")
			return
		}

		// Replay protection on the request ID.
		if lr.ID != "" && p.replay().Seen(cfg.IdpEntityID, lr.ID, time.Now().UTC().Add(p.cfg.ReplayCacheTTL)) {
			// Already processed — idempotent success.
			w.WriteHeader(http.StatusOK)
			return
		}

		// Map NameID → local user and terminate every session.
		provider := "saml:" + IssuerKeyFromEntityID(cfg.IdpEntityID)
		if ext, err := host.Repo().GetExternalIdentityByProviderAndExternalID(ctx, provider, nameID); err == nil && ext != nil {
			_, _ = host.Repo().DeleteUserSessions(ctx, ext.UserID)
			_, _ = host.Repo().RevokeAllUserRefreshTokens(ctx, ext.UserID)
		}
		// Clear this browser's session cookie too.
		http.SetCookie(w, auth.SessionCookie(cookieOptionsFromHost(host, r, -1), ""))

		// Reply with a LogoutResponse over the redirect binding when the IdP
		// published an SLO endpoint; otherwise a bare 200.
		if cfg.IdpSloURL != "" {
			if loc, err := p.buildLogoutResponseRedirect(host, cfg, r, lr.ID, relayState); err == nil {
				http.Redirect(w, r, loc, http.StatusFound)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}
}

// buildLogoutResponseRedirect builds a SAML LogoutResponse and returns the
// HTTP-Redirect binding URL to send the user back to the IdP's SLO endpoint.
func (p *ssoSAMLPlugin) buildLogoutResponseRedirect(host plugin.PluginHost, cfg *SamlConnectionConfig, r *http.Request, requestID, relayState string) (string, error) {
	sp, err := buildServiceProvider(cfg, host.BaseURL(), "", p.cfg.ClockSkew)
	if err != nil {
		return "", err
	}
	resp, err := sp.MakeLogoutResponse(cfg.IdpSloURL, requestID)
	if err != nil {
		return "", err
	}
	u := resp.Redirect(relayState)
	if u == nil {
		return "", errors.New("nil redirect")
	}
	return u.String(), nil
}

// --- redirect-binding signature verification --------------------------

// verifyRedirectSignature verifies a SAML HTTP-Redirect binding signature
// (SAML Bindings §3.4.4.1). The signed octet string is the raw, still-encoded
// query parameters in the canonical order SAMLRequest [, RelayState], SigAlg.
func verifyRedirectSignature(rawSource, sigAlg, signatureB64 string, cert *x509.Certificate) error {
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("idp cert is not RSA")
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return errors.New("signature not base64")
	}

	raw := parseRawQuery(rawSource)
	var b strings.Builder
	b.WriteString("SAMLRequest=")
	b.WriteString(raw["SAMLRequest"])
	if rs, ok := raw["RelayState"]; ok && rs != "" {
		b.WriteString("&RelayState=")
		b.WriteString(rs)
	}
	b.WriteString("&SigAlg=")
	b.WriteString(raw["SigAlg"])
	signed := []byte(b.String())

	var hash crypto.Hash
	var digest []byte
	switch sigAlg {
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
		hash = crypto.SHA256
		s := sha256.Sum256(signed)
		digest = s[:]
	case "http://www.w3.org/2000/09/xmldsig#rsa-sha1":
		hash = crypto.SHA1
		s := sha1.Sum(signed)
		digest = s[:]
	default:
		return errors.New("unsupported SigAlg")
	}
	return rsa.VerifyPKCS1v15(pub, hash, digest, sig)
}

// parseRawQuery splits a raw query/body string into key→raw(still-encoded)value
// without percent-decoding, so signature reconstruction is byte-exact.
func parseRawQuery(rawSource string) map[string]string {
	out := make(map[string]string)
	for _, pair := range strings.Split(rawSource, "&") {
		if pair == "" {
			continue
		}
		if eq := strings.IndexByte(pair, '='); eq >= 0 {
			out[pair[:eq]] = pair[eq+1:]
		} else {
			out[pair] = ""
		}
	}
	return out
}

func urlDecode(s string) string {
	v, err := url.QueryUnescape(s)
	if err != nil {
		return ""
	}
	return v
}

// inflateSAML base64-decodes then raw-DEFLATE-inflates a redirect-binding
// SAMLRequest into its XML bytes.
func inflateSAML(b64 string) ([]byte, error) {
	compressed, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	fr := flate.NewReader(bytes.NewReader(compressed))
	defer fr.Close()
	return io.ReadAll(io.LimitReader(fr, 1<<20))
}

func writeSLOError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	http.Error(w, msg, http.StatusBadRequest)
}
