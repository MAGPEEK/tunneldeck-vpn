package store

import (
	"errors"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/secret"
)

const (
	testCertificatePEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	testKeyPEM         = "-----BEGIN PRIVATE KEY-----\n" + secretValue + "\n-----END PRIVATE KEY-----\n"
)

func TestRemoteAccessDefaults(t *testing.T) {
	s, dir := newTestStore(t)
	if got := s.RemoteAccess(); got != domain.DefaultRemoteAccess() {
		t.Fatalf("RemoteAccess = %+v, want the defaults", got)
	}
	writeFile(t, dir, SettingsFileName, `{"schemaVersion":2,"language":"de","firewall":{"rules":[]}}`)
	if got := openTestStore(t, dir, newCipher(t, 1)).RemoteAccess(); got != domain.DefaultRemoteAccess() {
		t.Fatalf("RemoteAccess of a file without remoteAccess = %+v", got)
	}
	writeFile(t, dir, SettingsFileName, `{"schemaVersion":2,"remoteAccess":{"enabled":true}}`)
	want := domain.RemoteAccess{Enabled: true, Port: 8443, CertificateSource: domain.CertificateSelfSigned}
	if got := openTestStore(t, dir, newCipher(t, 1)).RemoteAccess(); got != want {
		t.Fatalf("RemoteAccess of a partial object = %+v, want %+v", got, want)
	}
}

func TestSetRemoteAccess(t *testing.T) {
	s, dir := newTestStore(t)
	settings := domain.RemoteAccess{Enabled: true, Port: 9443, CertificateSource: domain.CertificateUploaded}
	if err := s.SetRemoteAccess(settings); err != nil {
		t.Fatal(err)
	}
	if got := openTestStore(t, dir, newCipher(t, 1)).RemoteAccess(); got != settings {
		t.Fatalf("reloaded = %+v, want %+v", got, settings)
	}
	if err := s.SetRemoteAccess(domain.RemoteAccess{Port: 0, CertificateSource: "x"}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("invalid setting err = %v", err)
	}
	if got := s.RemoteAccess(); got != settings {
		t.Fatalf("setting after a rejected change = %+v", got)
	}
	if !strings.Contains(string(readFile(t, dir, SettingsFileName)), `"schemaVersion": 5`) {
		t.Error("schema version changed")
	}
}

func TestRemoteAccessKeyPairIsEncrypted(t *testing.T) {
	s, dir := newTestStore(t)
	if _, ok := s.RemoteAccessCertificate(domain.CertificateUploaded); ok {
		t.Fatal("certificate reported before any was stored")
	}
	if _, ok, err := s.RemoteAccessKeyPair(domain.CertificateSelfSigned); ok || err != nil {
		t.Fatalf("key pair before any was stored: %v, %v", ok, err)
	}
	pair := domain.KeyPair{CertificatePEM: testCertificatePEM, KeyPEM: testKeyPEM}
	if err := s.SetRemoteAccessKeyPair(domain.CertificateUploaded, pair); err != nil {
		t.Fatal(err)
	}
	assertNoSecret(t, SettingsFileName, string(readFile(t, dir, SettingsFileName)))

	reopened := openTestStore(t, dir, newCipher(t, 1))
	got, ok, err := reopened.RemoteAccessKeyPair(domain.CertificateUploaded)
	if err != nil || !ok || got != pair {
		t.Fatalf("RemoteAccessKeyPair = %+v, %v, %v", got, ok, err)
	}
	if certificate, ok := reopened.RemoteAccessCertificate(domain.CertificateUploaded); !ok || certificate != testCertificatePEM {
		t.Fatalf("RemoteAccessCertificate = %q, %v", certificate, ok)
	}
	if _, ok := reopened.RemoteAccessCertificate(domain.CertificateSelfSigned); ok {
		t.Fatal("the uploaded certificate filled the self-signed slot")
	}
	if err := reopened.SetRemoteAccess(domain.RemoteAccess{Port: 1443, CertificateSource: domain.CertificateSelfSigned}); err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.RemoteAccessCertificate(domain.CertificateUploaded); !ok {
		t.Fatal("changing the setting dropped the certificate")
	}
}

func TestSetRemoteAccessKeyPairValidation(t *testing.T) {
	s, _ := newTestStore(t)
	pair := domain.KeyPair{CertificatePEM: testCertificatePEM, KeyPEM: testKeyPEM}
	tests := []struct {
		name   string
		source domain.CertificateSource
		pair   domain.KeyPair
	}{
		{name: "unknown source", source: "acme", pair: pair},
		{name: "no key", source: domain.CertificateUploaded, pair: domain.KeyPair{CertificatePEM: testCertificatePEM}},
		{name: "no certificate", source: domain.CertificateUploaded, pair: domain.KeyPair{KeyPEM: testKeyPEM}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := s.SetRemoteAccessKeyPair(tt.source, tt.pair); !errors.Is(err, domain.ErrValidation) {
				t.Fatalf("err = %v, want ErrValidation", err)
			}
		})
	}
}

func TestSetRemoteAccessKeyPairEncryptFailure(t *testing.T) {
	s, _ := newTestStore(t)
	s.cipher = failingCipher{newCipher(t, 1)}
	err := s.SetRemoteAccessKeyPair(domain.CertificateUploaded, domain.KeyPair{CertificatePEM: testCertificatePEM, KeyPEM: testKeyPEM})
	if !errors.Is(err, errInjected) {
		t.Fatalf("err = %v, want the injected failure", err)
	}
	assertNoSecret(t, "error", err.Error())
}

func TestOpenRejectsBadRemoteAccess(t *testing.T) {
	s, dir := newTestStore(t)
	if err := s.SetRemoteAccessKeyPair(domain.CertificateSelfSigned, domain.KeyPair{CertificatePEM: testCertificatePEM, KeyPEM: testKeyPEM}); err != nil {
		t.Fatal(err)
	}
	_, err := open(dir, newCipher(t, 2), testDependencies(osFileSystem{}))
	if !errors.Is(err, secret.ErrWrongKeyOrTampered) {
		t.Fatalf("open with another key = %v, want ErrWrongKeyOrTampered", err)
	}
	assertNoSecret(t, "error", err.Error())

	writeFile(t, dir, SettingsFileName, `{"schemaVersion":2,"remoteAccess":{"port":70000}}`)
	if _, err := open(dir, newCipher(t, 1), testDependencies(osFileSystem{})); err == nil || !strings.Contains(err.Error(), "corrupted") {
		t.Fatalf("open with an invalid port = %v, want a corrupted error", err)
	}
}
