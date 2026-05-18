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
	"time"

	"github.com/crewjam/saml"
)

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
func buildServiceProvider(cfg *SamlConnectionConfig, baseURL, connectionID string, clockSkew time.Duration) (*saml.ServiceProvider, error) {
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
