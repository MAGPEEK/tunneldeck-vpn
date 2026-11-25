// Package remoteaccess serves the UI over HTTPS for clients coming through
// the tunnel (SPEC §8.1): it generates and renews the self-signed
// certificate, validates uploaded certificates and runs the HTTPS listener.
package remoteaccess

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"tunneldeck/internal/domain"
)

// Self-signed certificate parameters.
const (
	// SelfSignedName is the common name and first DNS name of the
	// self-signed certificate.
	SelfSignedName = "tunneldeck"
	// selfSignedYears is the validity of a self-signed certificate.
	selfSignedYears = 2
	// renewBefore is how long before expiry a certificate is renewed.
	renewBefore = 30 * 24 * time.Hour
	// clockSkew backdates NotBefore so clients with a slightly late clock
	// accept a fresh certificate.
	clockSkew = time.Hour
	// serialBits is the size of the random serial number.
	serialBits = 128
)

// PEM block types (RFC 7468).
const (
	pemCertificate = "CERTIFICATE"
	pemPrivateKey  = "PRIVATE KEY"
)

// errNoCertificate reports a PEM text without a CERTIFICATE block.
var errNoCertificate = errors.New("no PEM certificate found")

// CertificateInfo describes the leaf certificate of a chain. It holds no key
// material.
type CertificateInfo struct {
	Subject   string
	NotBefore time.Time
	NotAfter  time.Time
	// FingerprintSHA256 is the SHA-256 of the DER certificate as
	// colon-separated upper-case hex, as browsers and openssl show it.
	FingerprintSHA256 string
	// SelfSigned is true when the certificate is its own issuer.
	SelfSigned bool
}

// NeedsRenewal reports whether the certificate expires within 30 days of
// now, or already has.
func (c CertificateInfo) NeedsRenewal(now time.Time) bool {
	return !now.Before(c.NotAfter.Add(-renewBefore))
}

// GenerateSelfSigned returns a new ECDSA P-256 certificate for the names
// "tunneldeck" and "localhost", valid for two years from now, with a random
// serial number. The key is PKCS #8 PEM.
func GenerateSelfSigned(now time.Time) (domain.KeyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return domain.KeyPair{}, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialBits))
	if err != nil {
		return domain.KeyPair{}, fmt.Errorf("generate serial number: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: SelfSignedName},
		DNSNames:              []string{SelfSignedName, "localhost"},
		NotBefore:             now.Add(-clockSkew).UTC(),
		NotAfter:              now.AddDate(selfSignedYears, 0, 0).UTC(),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return domain.KeyPair{}, fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return domain.KeyPair{}, fmt.Errorf("encode key: %w", err)
	}
	return domain.KeyPair{
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: pemCertificate, Bytes: der})),
		KeyPEM:         string(pem.EncodeToMemory(&pem.Block{Type: pemPrivateKey, Bytes: keyDER})),
	}, nil
}

// Describe parses the first certificate of a PEM chain.
func Describe(certificatePEM string) (CertificateInfo, error) {
	chain, err := parseChain(certificatePEM)
	if err != nil {
		return CertificateInfo{}, err
	}
	return describe(chain[0]), nil
}

func describe(leaf *x509.Certificate) CertificateInfo {
	return CertificateInfo{
		Subject:           leaf.Subject.String(),
		NotBefore:         leaf.NotBefore.UTC(),
		NotAfter:          leaf.NotAfter.UTC(),
		FingerprintSHA256: Fingerprint(leaf.Raw),
		SelfSigned:        isSelfSigned(leaf),
	}
}

// Fingerprint returns the SHA-256 of der as colon-separated upper-case hex.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	encoded := strings.ToUpper(hex.EncodeToString(sum[:]))
	pairs := make([]string, 0, len(sum))
	for i := 0; i < len(encoded); i += 2 {
		pairs = append(pairs, encoded[i:i+2])
	}
	return strings.Join(pairs, ":")
}

// isSelfSigned checks the signature with the certificate's own key;
// CheckSignatureFrom would refuse a leaf that is not a CA.
func isSelfSigned(c *x509.Certificate) bool {
	return string(c.RawIssuer) == string(c.RawSubject) &&
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// parseChain decodes every PEM block of text; all must be certificates
// (RFC 7468 label CERTIFICATE). Text outside the blocks is ignored.
func parseChain(text string) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	rest := []byte(text)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != pemCertificate {
			return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate %d: %w", len(chain)+1, err)
		}
		chain = append(chain, certificate)
	}
	if len(chain) == 0 {
		return nil, errNoCertificate
	}
	return chain, nil
}

// encodeChain renders certificates as PEM, without explanatory text.
func encodeChain(chain []*x509.Certificate) string {
	var b strings.Builder
	for _, c := range chain {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: pemCertificate, Bytes: c.Raw}))
	}
	return b.String()
}
