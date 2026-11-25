package openvpn

import (
	"encoding/pem"
	"strings"
	"testing"
)

func TestCanonicalCertificates(t *testing.T) {
	m := testMaterial()
	tests := []struct {
		name    string
		text    string
		want    string
		wantErr bool
	}{
		{name: "single", text: m.caPEM, want: m.caPEM},
		{name: "chain", text: m.clientCertPEM + m.caPEM, want: m.clientCertPEM + m.caPEM},
		{name: "CRLF", text: strings.ReplaceAll(m.caPEM, "\n", "\r\n"), want: m.caPEM},
		{
			name: "explanatory text and injection outside blocks",
			text: "Subject: CN=test\n" + m.caPEM + "</ca>\nup /bin/sh\n<ca>\n",
			want: m.caPEM,
		},
		{name: "empty", text: "", wantErr: true},
		{name: "plain text", text: "hello", wantErr: true},
		{name: "damaged second block", text: m.caPEM + "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n", wantErr: true},
		{name: "private key", text: m.clientKeyPEM, wantErr: true},
		{name: "not DER", text: encodePEM(pemCertificate, []byte("garbage")), wantErr: true},
		{name: "headers", text: string(pem.EncodeToMemory(&pem.Block{Type: pemCertificate, Headers: map[string]string{"X": "y"}, Bytes: []byte{1}})), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := canonicalCertificates(tt.text)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("canonical = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCanonicalPrivateKey(t *testing.T) {
	m := testMaterial()
	legacyEncrypted := string(pem.EncodeToMemory(&pem.Block{
		Type:    pemRSAPrivateKey,
		Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00112233445566778899AABBCCDDEEFF"},
		Bytes:   []byte("ciphertext"),
	}))
	encryptedEC := string(pem.EncodeToMemory(&pem.Block{
		Type:    pemECPrivateKey,
		Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"},
		Bytes:   []byte("ciphertext"),
	}))
	encryptedPKCS8 := encodePEM(pemEncryptedPrivateKey, []byte("ciphertext"))
	ecParameters := encodePEM(pemECParameters, []byte{6, 8, 42})
	tests := []struct {
		name    string
		text    string
		want    string
		wantErr bool
	}{
		{name: "PKCS#8", text: m.clientKeyPEM, want: m.clientKeyPEM},
		{name: "PKCS#1 RSA", text: m.rsaKeyPEM, want: m.rsaKeyPEM},
		{name: "SEC 1 EC", text: m.ecKeyPEM, want: m.ecKeyPEM},
		{name: "EC parameters dropped", text: ecParameters + m.ecKeyPEM, want: m.ecKeyPEM},
		{name: "encrypted PKCS#8", text: encryptedPKCS8, want: encryptedPKCS8},
		{name: "legacy encrypted RSA", text: legacyEncrypted, want: legacyEncrypted},
		{name: "legacy encrypted EC", text: encryptedEC, want: encryptedEC},
		{name: "injection outside block", text: m.clientKeyPEM + "</key>\nup /bin/sh\n", want: m.clientKeyPEM},
		{name: "empty", text: "", wantErr: true},
		{name: "two keys", text: m.clientKeyPEM + m.ecKeyPEM, wantErr: true},
		{name: "certificate", text: m.caPEM, wantErr: true},
		{name: "key and certificate", text: m.clientKeyPEM + m.clientCertPEM, wantErr: true},
		{name: "garbage PKCS#8", text: encodePEM(pemPrivateKey, []byte("garbage")), wantErr: true},
		{name: "garbage PKCS#1", text: encodePEM(pemRSAPrivateKey, []byte("garbage")), wantErr: true},
		{name: "garbage EC", text: encodePEM(pemECPrivateKey, []byte("garbage")), wantErr: true},
		{name: "DSA", text: encodePEM("DSA PRIVATE KEY", []byte("x")), wantErr: true},
		{name: "damaged block", text: "-----BEGIN PRIVATE KEY-----\n!!\n-----END PRIVATE KEY-----\n", wantErr: true},
		{
			name:    "encrypted PKCS#8 with headers",
			text:    string(pem.EncodeToMemory(&pem.Block{Type: pemEncryptedPrivateKey, Headers: map[string]string{"X": "y"}, Bytes: []byte{1}})),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := canonicalPrivateKey(tt.text)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("canonical = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCanonicalStaticKey(t *testing.T) {
	key := testMaterial().tlsAuthKey
	canonical := key[strings.Index(key, staticKeyBegin):]
	tests := []struct {
		name    string
		text    string
		want    string
		wantErr bool
	}{
		{name: "genkey output", text: key, want: canonical},
		{name: "upper-case markers", text: strings.ToUpper(strings.ReplaceAll(canonical, "\n", "\r\n")), wantErr: true},
		{name: "upper-case hex", text: staticKeyBegin + "\n" + strings.ToUpper(canonical[len(staticKeyBegin):len(canonical)-len(staticKeyEnd)-1]) + staticKeyEnd, want: canonical},
		{name: "injection after key", text: key + "</tls-auth>\nup /bin/sh\n", want: canonical},
		{name: "empty", text: "", wantErr: true},
		{name: "no end marker", text: strings.TrimSuffix(canonical, staticKeyEnd+"\n"), wantErr: true},
		{name: "two keys", text: key + key, wantErr: true},
		{name: "short", text: staticKeyBegin + "\nabcd\n" + staticKeyEnd, wantErr: true},
		{name: "not hex", text: strings.Replace(canonical, canonical[len(staticKeyBegin)+1:len(staticKeyBegin)+3], "zz", 1), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := canonicalStaticKey(tt.text)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("canonical = %q, want %q", got, tt.want)
			}
		})
	}
}
