package remoteaccess

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 11, 25, 8, 30, 0, 0, time.UTC)

func TestGenerateSelfSigned(t *testing.T) {
	pair, err := GenerateSelfSigned(testNow)
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	if !strings.HasPrefix(pair.KeyPEM, "-----BEGIN PRIVATE KEY-----") {
		t.Errorf("key is not PKCS #8 PEM")
	}
	chain, err := parseChain(pair.CertificatePEM)
	if err != nil || len(chain) != 1 {
		t.Fatalf("parse = %v, %d certificates", err, len(chain))
	}
	leaf := chain[0]
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		t.Errorf("public key = %T, want ECDSA P-256", leaf.PublicKey)
	}
	if !slices.Equal(leaf.DNSNames, []string{"tunneldeck", "localhost"}) || leaf.Subject.CommonName != "tunneldeck" {
		t.Errorf("names = %v, CN %q", leaf.DNSNames, leaf.Subject.CommonName)
	}
	if want := testNow.AddDate(2, 0, 0); !leaf.NotAfter.Equal(want) || leaf.NotBefore.After(testNow) {
		t.Errorf("validity %s – %s, want until %s", leaf.NotBefore, leaf.NotAfter, want)
	}
	if leaf.SerialNumber.Sign() <= 0 {
		t.Errorf("serial number %v is not positive", leaf.SerialNumber)
	}
	if _, err := tls.X509KeyPair([]byte(pair.CertificatePEM), []byte(pair.KeyPEM)); err != nil {
		t.Errorf("crypto/tls rejects the pair: %v", err)
	}
	second, err := GenerateSelfSigned(testNow)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := parseChain(second.CertificatePEM)
	if other[0].SerialNumber.Cmp(leaf.SerialNumber) == 0 || second.KeyPEM == pair.KeyPEM {
		t.Error("two generations share serial number or key")
	}
}

func TestDescribe(t *testing.T) {
	pair, err := GenerateSelfSigned(testNow)
	if err != nil {
		t.Fatal(err)
	}
	info, err := Describe("explanatory text\n" + pair.CertificatePEM)
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	chain, _ := parseChain(pair.CertificatePEM)
	sum := sha256.Sum256(chain[0].Raw)
	if want := strings.ToUpper(hex.EncodeToString(sum[:])); strings.ReplaceAll(info.FingerprintSHA256, ":", "") != want {
		t.Errorf("fingerprint %s, want %s", info.FingerprintSHA256, want)
	}
	if !regexp.MustCompile(`^([0-9A-F]{2}:){31}[0-9A-F]{2}$`).MatchString(info.FingerprintSHA256) {
		t.Errorf("fingerprint format %q", info.FingerprintSHA256)
	}
	if info.Subject != "CN=tunneldeck" || !info.SelfSigned || info.NotAfter.Location() != time.UTC {
		t.Errorf("info = %+v", info)
	}

	for _, bad := range []string{"", "garbage", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"} {
		if _, err := Describe(bad); err == nil {
			t.Errorf("Describe(%q) succeeded", bad)
		}
	}
}

func TestDescribeCASignedCertificateIsNotSelfSigned(t *testing.T) {
	ca := newTestCA(t)
	leafPEM, _ := ca.issue(t, newECKey(t, elliptic.P256()), testNow.Add(-time.Hour), testNow.AddDate(1, 0, 0))
	info, err := Describe(leafPEM)
	if err != nil {
		t.Fatal(err)
	}
	if info.SelfSigned {
		t.Error("CA-signed leaf reported as self-signed")
	}
}

func TestNeedsRenewal(t *testing.T) {
	info := CertificateInfo{NotAfter: testNow}
	tests := []struct {
		name string
		now  time.Time
		want bool
	}{
		{name: "31 days left", now: testNow.Add(-31 * 24 * time.Hour), want: false},
		{name: "a minute more than 30 days left", now: testNow.Add(-30*24*time.Hour - time.Minute), want: false},
		{name: "exactly 30 days left", now: testNow.Add(-30 * 24 * time.Hour), want: true},
		{name: "one day left", now: testNow.Add(-24 * time.Hour), want: true},
		{name: "expired", now: testNow.Add(time.Hour), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := info.NeedsRenewal(tt.now); got != tt.want {
				t.Fatalf("NeedsRenewal = %v, want %v", got, tt.want)
			}
		})
	}
}
