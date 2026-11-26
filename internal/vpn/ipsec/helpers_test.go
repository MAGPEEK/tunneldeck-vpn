package ipsec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"tunneldeck/internal/domain"
)

// testPSK is a pre-shared key long enough for no advisory.
const testPSK = "correct-horse-battery-staple"

// profileWith returns an IPsec profile with settings and secrets; values
// of settings are strings or string lists.
func profileWith(settings map[string]any, secrets map[string]string) domain.Profile {
	s := domain.Settings{}
	for key, value := range settings {
		switch v := value.(type) {
		case string:
			s.SetString(key, v)
		case []string:
			s.SetStringList(key, v)
		case int:
			s.SetInt(key, v)
		}
	}
	return domain.Profile{Name: "Office", Protocol: domain.ProtocolIPsec, Settings: s, Secrets: secrets}
}

// pskProfile is a valid virtual IP profile with a pre-shared key.
func pskProfile() domain.Profile {
	return profileWith(map[string]any{KeyGateway: "vpn.example.com"}, map[string]string{SecretPSK: testPSK})
}

// testPKI is a throwaway CA with a client certificate signed by it.
type testPKI struct {
	caPEM, clientPEM, keyPEM string
	client                   *x509.Certificate
	key                      *ecdsa.PrivateKey
	ca                       *x509.Certificate
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	caKey := newKey(t)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	ca := sign(t, caTemplate, caTemplate, caKey, caKey)
	key := newKey(t)
	client := sign(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "client.example.com"},
		DNSNames: []string{"client.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}, ca, key, caKey)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return testPKI{
		caPEM: certificatePEM(ca), clientPEM: certificatePEM(client),
		keyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		client: client, key: key, ca: ca,
	}
}

// pkcs12 returns the client certificate, its key and the CA as a base64
// PKCS#12 bundle encrypted by encoder with password.
func (p testPKI) pkcs12(t *testing.T, encoder *pkcs12.Encoder, password string) string {
	t.Helper()
	der, err := encoder.Encode(p.key, p.client, []*x509.Certificate{p.ca}, password)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func sign(t *testing.T, template, parent *x509.Certificate, key, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// issueCodes returns the field codes of err, a *domain.ValidationError.
func issueCodes(t *testing.T, err error) map[string]string {
	t.Helper()
	codes := map[string]string{}
	if err == nil {
		return codes
	}
	v, ok := err.(*domain.ValidationError)
	if !ok {
		t.Fatalf("err = %T %v, want *domain.ValidationError", err, err)
	}
	for field, issue := range v.Issues {
		codes[field] = issue.Code
	}
	return codes
}
