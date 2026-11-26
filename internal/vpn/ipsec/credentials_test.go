package ipsec

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"software.sslmate.com/src/go-pkcs12"
)

func TestParsePrivateKey(t *testing.T) {
	pki := newTestPKI(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(pki.key)
	if err != nil {
		t.Fatal(err)
	}
	legacyEncrypted := "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----\n"
	tests := []struct {
		name    string
		text    string
		wantErr error
	}{
		{name: "PKCS#8", text: pki.keyPEM},
		{name: "PKCS#1", text: pemText("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey))},
		{name: "SEC 1", text: pemText("EC PRIVATE KEY", ecDER)},
		{name: "encrypted PKCS#8", text: pemText("ENCRYPTED PRIVATE KEY", []byte{1}), wantErr: errKeyEncrypted},
		{name: "encrypted legacy PEM", text: legacyEncrypted, wantErr: errKeyEncrypted},
		{name: "two keys", text: pki.keyPEM + pki.keyPEM, wantErr: errPrivateKeyInvalid},
		{name: "certificate", text: pki.caPEM, wantErr: errPrivateKeyInvalid},
		{name: "garbage", text: "key", wantErr: errPrivateKeyInvalid},
		{name: "broken DER", text: pemText("PRIVATE KEY", []byte{1, 2}), wantErr: errPrivateKeyInvalid},
		{name: "too large", text: strings.Repeat("x", maxPEMBytes+1), wantErr: errPrivateKeyInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parsePrivateKey(tt.text); !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func pemText(kind string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}))
}

func TestParseCertificates(t *testing.T) {
	pki := newTestPKI(t)
	tests := []struct {
		name string
		text string
		want int
	}{
		{name: "one", text: pki.caPEM, want: 1},
		{name: "chain", text: pki.clientPEM + "\n" + pki.caPEM, want: 2},
		{name: "trailing text", text: pki.caPEM + "x"},
		{name: "key", text: pki.keyPEM},
		{name: "empty", text: ""},
		{name: "broken DER", text: pemText("CERTIFICATE", []byte{1})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := parseCertificates(tt.text)
			if len(certs) != tt.want || (tt.want == 0) != (err != nil) {
				t.Errorf("certs = %d, err = %v", len(certs), err)
			}
		})
	}
}

func TestIdentityFromPKCS12(t *testing.T) {
	pki := newTestPKI(t)
	id, err := identityFromPKCS12(pki.pkcs12(t, pkcs12.Modern2023, "pw"), "pw")
	if err != nil || id.certificate.Subject.CommonName != "client.example.com" || len(id.chain) != 1 ||
		!strings.HasPrefix(id.keyPEM, "-----BEGIN PRIVATE KEY-----") {
		t.Fatalf("identity = %+v, %v", id, err)
	}
	if _, err := identityFromPKCS12("not base64!", "pw"); !errors.Is(err, errPKCS12Invalid) {
		t.Errorf("garbage: %v", err)
	}
	if _, err := identityFromPKCS12(base64.StdEncoding.EncodeToString([]byte("not a bundle")), "pw"); !errors.Is(err, errPKCS12Invalid) {
		t.Errorf("no bundle: %v", err)
	}
}
