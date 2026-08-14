// sp.go — bridge between SamlConnectionConfig and crewjam/saml's
// ServiceProvider type.
//
// The ServiceProvider is rebuilt per request from the connection
// config; we do not cache it because the cost is microseconds (parse
// a PEM cert, build a stub EntityDescriptor) and the alternative —
// caching with invalidation on PATCH — multiplies the failure modes
// for a feature that is rarely hit.
package ssosaml

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// sha1Refused is the operator-facing text for a refused SHA-1 XML
// signature. It names the escape hatch verbatim so whoever reads the
// server log learns the knob without reading this source.
const sha1Refused = "ssosaml: SHA-1 XML signatures are refused; set allow_sha1_signatures=true on this SAML connection to accept them, or reconfigure the IdP to sign with RSA-SHA256"

// sha1AlgorithmIDs is the closed set of SHA-1-based XML-DSig identifiers
// goxmldsig v1.6.0 will actually verify (xml_constants.go's
// signatureMethodsByIdentifier / digestAlgorithmsByIdentifier tables).
//
// A DENY-list, not an allow-list, and deliberately so: goxmldsig's tables
// are a closed set, so naming the four broken identifiers refuses exactly
// the defect. An allow-list of "the algorithms we like" would silently
// start rejecting ECDSA-SHA256/384/512 IdPs that work today, which is a
// second outage nobody asked for.
var sha1AlgorithmIDs = map[string]struct{}{
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1":        {},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1": {},
	"http://www.w3.org/2000/09/xmldsig#dsa-sha1":        {},
	"http://www.w3.org/2000/09/xmldsig#sha1":            {},
}

// algDenyListVerifier is a crewjam/saml SignatureVerifier that refuses
// SHA-1 signature and digest algorithms before delegating to the exact
// default it replaces (validationContext.Validate).
//
// WHAT WAS BROKEN: buildServiceProvider left ServiceProvider.SignatureVerifier
// nil, so crewjam's validateSignature fell through to
// dsig.NewDefaultValidationContext(...).Validate(el), and goxmldsig carries
// NO algorithm policy at all — RSA-SHA1 signatures and SHA-1 digests are in
// its identifier tables and verify happily. sp.SignatureMethod (below) pins
// RSA-SHA256 for OUTBOUND AuthnRequests only; it said nothing about what we
// ACCEPT. Not theoretical: crewjam's own IdentityProvider falls back to
// RSA-SHA1 when SignatureMethod is empty, as do ADFS 2.0 and legacy
// Shibboleth 2.x, so a real IdP downgrade lands in this exact code path.
// SHA-1 collisions are chosen-prefix-practical; XML's flexibility (comments,
// whitespace, attribute ordering) is unusually friendly to constructing the
// colliding pair.
//
// WHY THIS SHAPE: crewjam routes BOTH the Response signature and the
// Assertion signature through validateSignature, and calls this hook with an
// element that has already been namespace-detached, immediately in place of
// `validationContext.Validate(el)`. Delegating at the end therefore preserves
// every existing check (certificate store, reference resolution, canonical
// digest) and adds only the algorithm refusal.
type algDenyListVerifier struct {
	// allowSHA1 is the per-connection escape hatch
	// (SamlConnectionConfig.AllowSHA1Signatures). Default false.
	allowSHA1 bool
}

// VerifySignature implements saml.SignatureVerifier.
func (v algDenyListVerifier) VerifySignature(vc *dsig.ValidationContext, el *etree.Element) error {
	if !v.allowSHA1 {
		// DESCENDANT paths (".//"), not direct children. goxmldsig's own
		// findSignature walks the WHOLE subtree and validates the FIRST
		// <Signature> it finds anywhere, so a guard that only inspected
		// ./Signature/... could be bypassed by nesting the forged SHA-1
		// signature inside e.g. <saml:Issuer> (found first, depth-first)
		// and leaving a decoy RSA-SHA256 Signature as the direct child.
		// etree matches tags prefix-agnostically, so ds:SignedInfo hits.
		for _, m := range el.FindElements(".//SignedInfo/SignatureMethod") {
			if _, bad := sha1AlgorithmIDs[m.SelectAttrValue("Algorithm", "")]; bad {
				return errors.New(sha1Refused + " (signature method " + m.SelectAttrValue("Algorithm", "") + ")")
			}
		}
		// Scoped to SignedInfo/Reference deliberately. A whole-document
		// scan for a SHA-1 DigestMethod would refuse every legitimate
		// WantEncryptedAssertions login: <ds:DigestMethod Algorithm=
		// "...xmldsig#sha1"/> is the STANDARD child of <xenc:EncryptionMethod
		// Algorithm="...rsa-oaep-mgf1p">, where it is a mask-generation
		// parameter and not a signature integrity claim.
		for _, d := range el.FindElements(".//SignedInfo/Reference/DigestMethod") {
			if _, bad := sha1AlgorithmIDs[d.SelectAttrValue("Algorithm", "")]; bad {
				return errors.New(sha1Refused + " (digest method " + d.SelectAttrValue("Algorithm", "") + ")")
			}
		}
	}
	_, err := vc.Validate(el)
	return err
}

// buildServiceProvider hydrates a crewjam/saml ServiceProvider from a
// SamlConnectionConfig + the yauth deployment's base URL. The returned
// SP enforces the connection's signature requirements (default: both
// Response and Assertion must be signed) and pins ACS / EntityID to
// the connection's configured values.
//
// The connectionID is appended into the default SP entity ID when
// SpEntityID is empty — so two SAML connections in the same yauth
// deployment have distinct entity IDs, preventing an IdP that was
// configured for connection A from accepting an assertion for
// connection B.
// The clock-skew tolerance is NOT a parameter here: crewjam exposes it
// only as the package-level saml.MaxClockSkew, which ssosaml.New() now
// sets from Config.ClockSkew. This function used to take a clockSkew
// argument that its body never read, so every caller believed it was
// configuring something it was not.
func buildServiceProvider(cfg *SamlConnectionConfig, baseURL, connectionID string) (*saml.ServiceProvider, error) {
	idpCert, err := parsePEMCert(cfg.IdpX509Cert)
	if err != nil {
		return nil, fmt.Errorf("ssosaml: parse idp cert: %w", err)
	}

	acsRaw := cfg.ACSURLForConnection(baseURL)
	acsURL, err := url.Parse(acsRaw)
	if err != nil {
		return nil, fmt.Errorf("ssosaml: parse acs url %q: %w", acsRaw, err)
	}
	entityID := cfg.EntityIDForConnection(baseURL, connectionID)

	idpEntityDescriptor := buildIdpEntityDescriptor(cfg, idpCert)

	sp := &saml.ServiceProvider{
		EntityID:    entityID,
		AcsURL:      *acsURL,
		MetadataURL: *acsURL, // matches AcsURL by default; harmless
		IDPMetadata: idpEntityDescriptor,
		// AllowIDPInitiated: opt-in per connection. Default off is the
		// secure choice; the IdP-initiated path skips request-id
		// binding and is the historical attack surface.
		AllowIDPInitiated: cfg.IdpInitiatedSsoAllowed,
		// Algorithm policy for INBOUND signatures. Without this crewjam
		// falls back to goxmldsig's default context, which has none —
		// see algDenyListVerifier. The hatch is per connection and off
		// by default, because the only honest migration story for a shop
		// wired to an ADFS 2.0 / Shibboleth 2.x IdP is "turn it on for
		// that one connection while you move the IdP".
		SignatureVerifier: algDenyListVerifier{allowSHA1: cfg.AllowSHA1Signatures},
	}

	// SP signing key (optional — only required for signed AuthnRequest
	// and decrypting encrypted assertions).
	if cfg.SignAuthnRequests || cfg.WantEncryptedAssertions {
		if cfg.SpPrivateKey == nil || cfg.SpCertificate == nil {
			return nil, errors.New("ssosaml: sp_private_key + sp_certificate required for signing / decryption")
		}
		keyPair, err := tls.X509KeyPair([]byte(*cfg.SpCertificate), []byte(*cfg.SpPrivateKey))
		if err != nil {
			return nil, fmt.Errorf("ssosaml: parse sp keypair: %w", err)
		}
		rsaKey, ok := keyPair.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("ssosaml: sp_private_key must be RSA")
		}
		spCert, err := x509.ParseCertificate(keyPair.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("ssosaml: parse sp cert: %w", err)
		}
		sp.Key = rsaKey
		sp.Certificate = spCert
		if cfg.SignAuthnRequests {
			// crewjam/saml interprets a non-empty SignatureMethod as
			// "sign every AuthnRequest". RSA-SHA256 is the modern
			// default; SHA1 is permitted by SAML but deprecated.
			sp.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
		}
	}

	return sp, nil
}

// buildIdpEntityDescriptor constructs a minimal crewjam/saml
// EntityDescriptor describing the IdP, hydrated from the connection's
// configured URL + cert. This is what crewjam/saml uses to know where
// to send AuthnRequests and which key to verify signatures against.
//
// We construct it from connection config rather than parsing a real
// metadata.xml because the connection config is the single source of
// truth — admins paste cert + URL once; we never trust an unverified
// metadata URL at login time.
func buildIdpEntityDescriptor(cfg *SamlConnectionConfig, idpCert *x509.Certificate) *saml.EntityDescriptor {
	certB64 := encodeCertBase64(idpCert)

	keyDescriptors := []saml.KeyDescriptor{
		{
			Use: "signing",
			KeyInfo: saml.KeyInfo{
				X509Data: saml.X509Data{
					X509Certificates: []saml.X509Certificate{{Data: certB64}},
				},
			},
		},
	}

	idpSSO := saml.IDPSSODescriptor{
		SSODescriptor: saml.SSODescriptor{
			RoleDescriptor: saml.RoleDescriptor{
				ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
				KeyDescriptors:             keyDescriptors,
			},
		},
		SingleSignOnServices: []saml.Endpoint{
			{
				Binding:  saml.HTTPRedirectBinding,
				Location: cfg.IdpSsoURL,
			},
			{
				Binding:  saml.HTTPPostBinding,
				Location: cfg.IdpSsoURL,
			},
		},
	}
	if cfg.IdpSloURL != "" {
		idpSSO.SingleLogoutServices = []saml.Endpoint{
			{Binding: saml.HTTPRedirectBinding, Location: cfg.IdpSloURL},
			{Binding: saml.HTTPPostBinding, Location: cfg.IdpSloURL},
		}
	}

	return &saml.EntityDescriptor{
		EntityID:          cfg.IdpEntityID,
		IDPSSODescriptors: []saml.IDPSSODescriptor{idpSSO},
	}
}

// parsePEMCert decodes a PEM-armored X.509 certificate. Multiple
// CERTIFICATE blocks are tolerated — the first one is returned (the
// rest are intermediates; crewjam/saml does not currently verify
// against a chain).
func parsePEMCert(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("ssosaml: no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("ssosaml: PEM block type %q is not CERTIFICATE", block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ssosaml: parse certificate: %w", err)
	}
	return cert, nil
}

// encodeCertBase64 emits the DER bytes of a cert as a single base64
// string (no PEM armor). This is the form expected inside
// <ds:X509Certificate> in SAML metadata.
func encodeCertBase64(cert *x509.Certificate) string {
	// We use the standard PEM encoder and strip the armor — it
	// always emits standard base64 (with \n line wrapping crewjam/saml
	// tolerates).
	armored := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	// Strip the BEGIN/END lines; keep the base64 body intact.
	out := []byte{}
	inBody := false
	for _, line := range splitLines(armored) {
		switch {
		case len(line) >= 5 && string(line[:5]) == "-----":
			if inBody {
				return string(out)
			}
			inBody = true
		case inBody:
			out = append(out, line...)
		}
	}
	return string(out)
}

func splitLines(b []byte) [][]byte {
	out := [][]byte{}
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}
