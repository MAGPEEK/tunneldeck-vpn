package remoteaccess

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func newECKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func pemOf(blockType string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

func pkcs8PEM(t *testing.T, key crypto.Signer) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pemOf("PRIVATE KEY", der)
}

// createCertificate signs a certificate for key with signer; a nil parent
// makes it self-signed.
func createCertificate(t *testing.T, template, parent *x509.Certificate, key crypto.PublicKey, signer crypto.Signer) (*x509.Certificate, string) {
	t.Helper()
	if parent == nil {
		parent = template
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key, signer)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, pemOf("CERTIFICATE", der)
}

var nextSerial int64

func leafTemplate(name string, notBefore, notAfter time.Time) *x509.Certificate {
	nextSerial++
	return &x509.Certificate{
		SerialNumber: big.NewInt(nextSerial),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

// selfSignedPEM returns a self-signed certificate for key.
func selfSignedPEM(t *testing.T, key crypto.Signer, notBefore, notAfter time.Time) string {
	t.Helper()
	_, certificatePEM := createCertificate(t, leafTemplate("nas.example.com", notBefore, notAfter), nil, key.Public(), key)
	return certificatePEM
}

type testCA struct {
	certificate *x509.Certificate
	pem         string
	key         *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key := newECKey(t, elliptic.P256())
	template := leafTemplate("Test CA", testNow.AddDate(-1, 0, 0), testNow.AddDate(5, 0, 0))
	template.IsCA, template.BasicConstraintsValid = true, true
	template.KeyUsage = x509.KeyUsageCertSign
	certificate, certificatePEM := createCertificate(t, template, nil, key.Public(), key)
	return testCA{certificate: certificate, pem: certificatePEM, key: key}
}

// issue returns a leaf for key signed by the CA, and the chain leaf + CA.
func (ca testCA) issue(t *testing.T, key crypto.Signer, notBefore, notAfter time.Time) (leafPEM, chainPEM string) {
	t.Helper()
	_, leafPEM = createCertificate(t, leafTemplate("nas.example.com", notBefore, notAfter), ca.certificate, key.Public(), ca.key)
	return leafPEM, leafPEM + ca.pem
}
