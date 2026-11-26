package remoteaccess

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"tunneldeck/internal/domain"
)

func newRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestParseUploadAcceptsSupportedKeys(t *testing.T) {
	validFrom, validTo := testNow.Add(-time.Hour), testNow.AddDate(1, 0, 0)
	ca := newTestCA(t)
	ecKey := newECKey(t, elliptic.P256())
	_, chainPEM := ca.issue(t, ecKey, validFrom, validTo)
	p384 := newECKey(t, elliptic.P384())
	p384DER, err := x509.MarshalECPrivateKey(p384)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey := newRSAKey(t, 2048)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name           string
		certificatePEM string
		keyPEM         string
		chainLength    int
	}{
		{name: "ECDSA P-256 chain with explanatory text", certificatePEM: "Subject: nas\n" + chainPEM + "trailing note\n", keyPEM: "key follows\n" + pkcs8PEM(t, ecKey), chainLength: 2},
		{name: "ECDSA P-384 SEC 1", certificatePEM: selfSignedPEM(t, p384, validFrom, validTo), keyPEM: pemOf("EC PRIVATE KEY", p384DER), chainLength: 1},
		{name: "RSA 2048 PKCS #1", certificatePEM: selfSignedPEM(t, rsaKey, validFrom, validTo), keyPEM: pemOf("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey)), chainLength: 1},
		{name: "Ed25519", certificatePEM: selfSignedPEM(t, edKey, validFrom, validTo), keyPEM: pkcs8PEM(t, edKey), chainLength: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pair, err := ParseUpload(tt.certificatePEM, tt.keyPEM, testNow)
			if err != nil {
				t.Fatalf("ParseUpload: %v", err)
			}
			chain, err := parseChain(pair.CertificatePEM)
			if err != nil || len(chain) != tt.chainLength {
				t.Fatalf("stored chain: %v, %d certificates", err, len(chain))
			}
			if strings.Contains(pair.CertificatePEM+pair.KeyPEM, "note") || strings.Contains(pair.KeyPEM, "follows") {
				t.Error("explanatory text kept")
			}
			if !strings.HasPrefix(pair.KeyPEM, "-----BEGIN PRIVATE KEY-----") {
				t.Error("key not normalised to PKCS #8")
			}
			if _, err := tls.X509KeyPair([]byte(pair.CertificatePEM), []byte(pair.KeyPEM)); err != nil {
				t.Errorf("crypto/tls rejects the stored pair: %v", err)
			}
		})
	}
}

func TestParseUploadRejects(t *testing.T) {
	validFrom, validTo := testNow.Add(-time.Hour), testNow.AddDate(1, 0, 0)
	key := newECKey(t, elliptic.P256())
	certificatePEM := selfSignedPEM(t, key, validFrom, validTo)
	keyPEM := pkcs8PEM(t, key)
	weakRSA := newRSAKey(t, 1024)
	p224 := newECKey(t, elliptic.P224())
	p224DER, err := x509.MarshalECPrivateKey(p224)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name           string
		certificatePEM string
		keyPEM         string
		field          string
		message        string
	}{
		{name: "mismatched key", certificatePEM: certificatePEM, keyPEM: pkcs8PEM(t, newECKey(t, elliptic.P256())), field: "keyPem", message: "does not belong"},
		{name: "expired", certificatePEM: selfSignedPEM(t, key, testNow.AddDate(-2, 0, 0), testNow.Add(-time.Second)), keyPEM: keyPEM, field: "certificatePem", message: "expired"},
		{name: "not valid yet", certificatePEM: selfSignedPEM(t, key, testNow.Add(time.Hour), validTo), keyPEM: keyPEM, field: "certificatePem", message: "not valid yet"},
		{name: "garbage certificate", certificatePEM: "not a certificate", keyPEM: keyPEM, field: "certificatePem", message: "PEM certificate"},
		{name: "corrupt certificate block", certificatePEM: pemOf("CERTIFICATE", []byte("junk")), keyPEM: keyPEM, field: "certificatePem", message: "PEM certificate"},
		{name: "key in the certificate field", certificatePEM: certificatePEM + keyPEM, keyPEM: keyPEM, field: "certificatePem", message: "PEM certificate"},
		{name: "garbage key", certificatePEM: certificatePEM, keyPEM: "not a key", field: "keyPem", message: "exactly one"},
		{name: "two keys", certificatePEM: certificatePEM, keyPEM: keyPEM + keyPEM, field: "keyPem", message: "exactly one"},
		{name: "certificate in the key field", certificatePEM: certificatePEM, keyPEM: certificatePEM, field: "keyPem", message: "exactly one"},
		{name: "encrypted PKCS #8", certificatePEM: certificatePEM, keyPEM: pemOf("ENCRYPTED PRIVATE KEY", []byte("x")), field: "keyPem", message: "encrypted"},
		{name: "corrupt key block", certificatePEM: certificatePEM, keyPEM: pemOf("PRIVATE KEY", []byte("junk")), field: "keyPem", message: "cannot be parsed"},
		{name: "RSA 1024", certificatePEM: selfSignedPEM(t, weakRSA, validFrom, validTo), keyPEM: pkcs8PEM(t, weakRSA), field: "keyPem", message: "at least 2048"},
		{name: "ECDSA P-224", certificatePEM: certificatePEM, keyPEM: pemOf("EC PRIVATE KEY", p224DER), field: "keyPem", message: "P-256"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseUpload(tt.certificatePEM, tt.keyPEM, testNow)
			var v *domain.ValidationError
			if !errors.As(err, &v) {
				t.Fatalf("err = %v, want a ValidationError", err)
			}
			if !strings.Contains(v.Fields[tt.field], tt.message) {
				t.Fatalf("fields = %v, want %s containing %q", v.Fields, tt.field, tt.message)
			}
			if code := v.Issues[tt.field].Code; !strings.HasPrefix(code, "remote_access_") {
				t.Errorf("code of %s = %q, want a remote_access_ code", tt.field, code)
			}
			if strings.Contains(err.Error(), "BEGIN") || strings.Contains(err.Error(), "MII") {
				t.Errorf("error quotes the upload: %v", err)
			}
		})
	}
}

func TestParseUploadReportsBothFields(t *testing.T) {
	_, err := ParseUpload("x", "y", testNow)
	var v *domain.ValidationError
	if !errors.As(err, &v) || v.Fields["certificatePem"] == "" || v.Fields["keyPem"] == "" {
		t.Fatalf("err = %v, want both fields", err)
	}
}
