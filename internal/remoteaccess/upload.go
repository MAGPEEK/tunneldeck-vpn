package remoteaccess

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"tunneldeck/internal/domain"
)

// minRSABits is the smallest accepted RSA key.
const minRSABits = 2048

// Validation fields of an upload, named like the API request members.
const (
	fieldCertificate = "certificatePem"
	fieldKey         = "keyPem"
)

// Key problems; messages never quote the submitted text.
var (
	errKeyNotPEM       = errors.New("must hold exactly one PEM private key")
	errKeyEncrypted    = errors.New("must not be encrypted")
	errKeyUnsupported  = errors.New("must be an RSA key of at least 2048 bits, an ECDSA P-256 or P-384 key, or an Ed25519 key")
	errKeyUnparseable  = errors.New("cannot be parsed")
	errKeyMismatch     = errors.New("does not belong to the certificate")
	errCertNotYetValid = errors.New("is not valid yet")
	errCertExpired     = errors.New("has expired")
)

// uploadIssues are the stable codes of the upload problems.
var uploadIssues = map[error]string{
	errKeyNotPEM:       "remote_access_key_not_pem",
	errKeyEncrypted:    "remote_access_key_encrypted",
	errKeyUnsupported:  "remote_access_key_unsupported",
	errKeyUnparseable:  "remote_access_key_unparseable",
	errKeyMismatch:     "remote_access_key_mismatch",
	errCertNotYetValid: "remote_access_certificate_not_yet_valid",
	errCertExpired:     "remote_access_certificate_expired",
}

// uploadError records problem for field, with its code when it is one of
// the upload errors.
func uploadError(v *domain.ValidationError, field string, problem error) {
	if code, ok := uploadIssues[problem]; ok {
		v.AddIssue(field, domain.Issue(code), problem.Error())
		return
	}
	v.Add(field, problem.Error())
}

// ParseUpload validates an uploaded PEM certificate chain (leaf first) and
// private key (RFC 7468): the key must be RSA ≥ 2048 bits, ECDSA P-256/P-384
// or Ed25519, unencrypted, and belong to the leaf, which must be valid at
// now. It returns the pair re-encoded without explanatory text, the key as
// PKCS #8. Failures are a *domain.ValidationError with the fields
// "certificatePem" and "keyPem".
func ParseUpload(certificatePEM, keyPEM string, now time.Time) (domain.KeyPair, error) {
	v := &domain.ValidationError{}
	chain, err := parseChain(certificatePEM)
	if err != nil {
		v.AddIssue(fieldCertificate, domain.Issue("remote_access_certificate_invalid"), "must be a PEM certificate chain, leaf first")
	} else if err := checkValidity(chain[0], now); err != nil {
		uploadError(v, fieldCertificate, err)
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		uploadError(v, fieldKey, err)
	}
	if len(v.Fields) > 0 {
		return domain.KeyPair{}, v
	}
	if !publicKeysEqual(chain[0].PublicKey, key.Public()) {
		return domain.KeyPair{}, keyError(errKeyMismatch)
	}
	return encodePair(chain, key)
}

func checkValidity(leaf *x509.Certificate, now time.Time) error {
	switch {
	case now.Before(leaf.NotBefore):
		return errCertNotYetValid
	case now.After(leaf.NotAfter):
		return errCertExpired
	}
	return nil
}

// parseKey decodes exactly one unencrypted PEM private key of a supported
// type and strength.
func parseKey(text string) (crypto.Signer, error) {
	block, rest := pem.Decode([]byte(text))
	if block == nil {
		return nil, errKeyNotPEM
	}
	if next, _ := pem.Decode(rest); next != nil {
		return nil, errKeyNotPEM
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" || block.Headers["Proc-Type"] != "" {
		return nil, errKeyEncrypted
	}
	key, err := parseKeyBlock(block)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok || !strongEnough(signer) {
		return nil, errKeyUnsupported
	}
	return signer, nil
}

func parseKeyBlock(block *pem.Block) (any, error) {
	var key any
	var err error
	switch block.Type {
	case pemPrivateKey:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, errKeyNotPEM
	}
	if err != nil {
		return nil, errKeyUnparseable
	}
	return key, nil
}

func strongEnough(key crypto.Signer) bool {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k.N.BitLen() >= minRSABits
	case *ecdsa.PrivateKey:
		return k.Curve == elliptic.P256() || k.Curve == elliptic.P384()
	case ed25519.PrivateKey:
		return true
	}
	return false
}

func publicKeysEqual(certificateKey, key crypto.PublicKey) bool {
	equaler, ok := certificateKey.(interface{ Equal(crypto.PublicKey) bool })
	return ok && equaler.Equal(key)
}

// encodePair renders the validated pair and proves that crypto/tls accepts
// it.
func encodePair(chain []*x509.Certificate, key crypto.Signer) (domain.KeyPair, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return domain.KeyPair{}, keyError(errKeyUnsupported)
	}
	pair := domain.KeyPair{
		CertificatePEM: encodeChain(chain),
		KeyPEM:         string(pem.EncodeToMemory(&pem.Block{Type: pemPrivateKey, Bytes: der})),
	}
	if _, err := tls.X509KeyPair([]byte(pair.CertificatePEM), []byte(pair.KeyPEM)); err != nil {
		return domain.KeyPair{}, keyError(errKeyMismatch)
	}
	return pair, nil
}

func keyError(problem error) *domain.ValidationError {
	v := &domain.ValidationError{}
	uploadError(v, fieldKey, problem)
	return v
}
