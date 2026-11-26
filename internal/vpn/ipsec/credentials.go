package ipsec

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

// Limits of the key material fields.
const (
	maxPEMBytes    = 64 << 10
	maxPKCS12Bytes = 64 << 10
)

// Errors of the key material checks; settings maps them to field codes.
// None of them repeats the material.
var (
	errCertificateInvalid = errors.New("must contain one or more PEM certificates (RFC 7468)")
	errPrivateKeyInvalid  = errors.New("must contain exactly one unencrypted PEM private key (RFC 7468)")
	errKeyEncrypted       = errors.New("is encrypted; upload the key without a passphrase or a PKCS#12 file with its password")
	errKeyMismatch        = errors.New("does not belong to the client certificate")
	errPKCS12Invalid      = errors.New("must be a base64-encoded PKCS#12 file (.p12, .pfx) of at most 64 KiB with a certificate and its key")
	errPKCS12Password     = errors.New("the PKCS#12 password is wrong")
)

// clientIdentity is the certificate and key the profile authenticates
// with, ready for charon: PEM of the certificate, of the certificates
// sent along with it (its chain) and of the key in PKCS#8.
type clientIdentity struct {
	certificate *x509.Certificate
	chain       []*x509.Certificate
	keyPEM      string
}

// parseCertificates reads one or more PEM certificates and nothing else.
func parseCertificates(text string) ([]*x509.Certificate, error) {
	if len(text) > maxPEMBytes {
		return nil, errCertificateInvalid
	}
	var certs []*x509.Certificate
	rest := []byte(text)
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, errCertificateInvalid
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errCertificateInvalid
		}
		certs, rest = append(certs, cert), next
	}
	if len(certs) == 0 || len(bytes.TrimSpace(rest)) > 0 {
		return nil, errCertificateInvalid
	}
	return certs, nil
}

// parsePrivateKey reads exactly one unencrypted PEM private key: PKCS#8,
// PKCS#1 (RSA) or SEC 1 (EC).
func parsePrivateKey(text string) (crypto.Signer, error) {
	if len(text) > maxPEMBytes {
		return nil, errPrivateKeyInvalid
	}
	block, rest := pem.Decode([]byte(text))
	switch {
	case block == nil || len(bytes.TrimSpace(rest)) > 0:
		return nil, errPrivateKeyInvalid
	case block.Type == "ENCRYPTED PRIVATE KEY" || strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED"):
		return nil, errKeyEncrypted
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, errPrivateKeyInvalid
	}
	signer, ok := key.(crypto.Signer)
	if err != nil || !ok {
		return nil, errPrivateKeyInvalid
	}
	return signer, nil
}

// identityFromPEM pairs the PEM client certificate (followed by its chain)
// with the PEM key.
func identityFromPEM(certText, keyText string) (clientIdentity, error) {
	certs, err := parseCertificates(certText)
	if err != nil {
		return clientIdentity{}, err
	}
	key, err := parsePrivateKey(keyText)
	if err != nil {
		return clientIdentity{}, err
	}
	return newClientIdentity(key, certs[0], certs[1:])
}

// identityFromPKCS12 decodes a base64 PKCS#12 bundle (RFC 7292) with its
// password: the key, its certificate and the certificates sent along.
// Modern (PBES2, AES) and legacy (3DES, RC2) encryption are read.
func identityFromPKCS12(bundle, password string) (clientIdentity, error) {
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(bundle), ""))
	if err != nil || len(der) == 0 || len(der) > maxPKCS12Bytes {
		return clientIdentity{}, errPKCS12Invalid
	}
	key, cert, chain, err := pkcs12.DecodeChain(der, password)
	switch {
	case errors.Is(err, pkcs12.ErrIncorrectPassword):
		return clientIdentity{}, errPKCS12Password
	case err != nil:
		return clientIdentity{}, errPKCS12Invalid
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return clientIdentity{}, errPKCS12Invalid
	}
	return newClientIdentity(signer, cert, chain)
}

func newClientIdentity(key crypto.Signer, cert *x509.Certificate, chain []*x509.Certificate) (clientIdentity, error) {
	public, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !public.Equal(cert.PublicKey) {
		return clientIdentity{}, errKeyMismatch
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return clientIdentity{}, errPrivateKeyInvalid
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	return clientIdentity{certificate: cert, chain: chain, keyPEM: keyPEM}, nil
}

// certificatePEM encodes cert as one PEM block.
func certificatePEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}
