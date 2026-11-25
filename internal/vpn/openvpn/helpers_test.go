package openvpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata")

// testOptions are the render options used by the golden files.
var testOptions = RenderOptions{ManagementSocket: "/run/tunneldeck/mgmt.sock", DeviceName: "tdvpn0"}

// material is test key material, generated once per test run so that no
// private key is committed.
type material struct {
	caPEM, clientCertPEM, clientKeyPEM string
	rsaKeyPEM, ecKeyPEM                string
	tlsAuthKey, tlsCryptKey            string
}

var testMaterial = sync.OnceValue(func() material {
	caKey := mustECKey()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TunnelDeck test CA"},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(0, 0).AddDate(100, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER := mustCert(caTemplate, caTemplate, &caKey.PublicKey, caKey)
	clientKey := mustECKey()
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(0, 0).AddDate(100, 0, 0),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		panic(err)
	}
	clientDER := mustCert(clientTemplate, caCert, &clientKey.PublicKey, caKey)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		panic(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		panic(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return material{
		caPEM:         encodePEM(pemCertificate, caDER),
		clientCertPEM: encodePEM(pemCertificate, clientDER),
		clientKeyPEM:  encodePEM(pemPrivateKey, pkcs8),
		ecKeyPEM:      encodePEM(pemECPrivateKey, ecDER),
		rsaKeyPEM:     encodePEM(pemRSAPrivateKey, x509.MarshalPKCS1PrivateKey(rsaKey)),
		tlsAuthKey:    staticKey(),
		tlsCryptKey:   staticKey(),
	}
})

func mustECKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}

func mustCert(template, parent *x509.Certificate, pub any, signer any) []byte {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if err != nil {
		panic(err)
	}
	return der
}

func encodePEM(blockType string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

// staticKey returns a random key in the layout of "openvpn --genkey",
// comment header included.
func staticKey() string {
	key := make([]byte, staticKeyBytes)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	encoded := hex.EncodeToString(key)
	var b strings.Builder
	b.WriteString("#\n# 2048 bit OpenVPN static key\n#\n" + staticKeyBegin + "\n")
	for i := 0; i < len(encoded); i += staticKeyHexLine {
		b.WriteString(encoded[i:i+staticKeyHexLine] + "\n")
	}
	b.WriteString(staticKeyEnd + "\n")
	return b.String()
}

// redact replaces the generated key material in text with the placeholders
// of docs/openvpn-notes.md, so golden files are stable.
func redact(t *testing.T, text string) string {
	t.Helper()
	m := testMaterial()
	replacements := []struct{ value, placeholder string }{
		{m.caPEM, "<CA PEM>\n"},
		{m.clientCertPEM, "<CLIENT CERT PEM>\n"},
		{m.clientKeyPEM, "<CLIENT KEY PEM>\n"},
		{mustCanonicalStaticKey(t, m.tlsAuthKey), "<TLS AUTH KEY>\n"},
		{mustCanonicalStaticKey(t, m.tlsCryptKey), "<TLS CRYPT KEY>\n"},
	}
	for _, r := range replacements {
		text = strings.ReplaceAll(text, r.value, r.placeholder)
	}
	return text
}

// unredact fills the placeholders of a testdata file with key material.
func unredact(text string) string {
	m := testMaterial()
	return strings.NewReplacer(
		"<CA PEM>\n", m.caPEM,
		"<CLIENT CERT PEM>\n", m.clientCertPEM,
		"<CLIENT KEY PEM>\n", m.clientKeyPEM,
		"<TLS AUTH KEY>\n", m.tlsAuthKey,
		"<TLS CRYPT KEY>\n", m.tlsCryptKey,
	).Replace(text)
}

func mustCanonicalStaticKey(t *testing.T, text string) string {
	t.Helper()
	canonical, err := canonicalStaticKey(text)
	if err != nil {
		t.Fatalf("canonicalStaticKey: %v", err)
	}
	return canonical
}

// assertGolden compares got with testdata/name, or rewrites the file when
// the test runs with -update.
func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want := readTestdata(t, name)
	if got != want {
		t.Errorf("%s differs from golden file\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// newProfile builds an OpenVPN profile from plain setting values.
func newProfile(t *testing.T, settings map[string]any, secrets vpn.Secrets) domain.Profile {
	t.Helper()
	s := domain.Settings{}
	for key, value := range settings {
		switch v := value.(type) {
		case string:
			s.SetString(key, v)
		case int:
			s.SetInt(key, v)
		case bool:
			s.SetBool(key, v)
		case []string:
			s.SetStringList(key, v)
		default:
			t.Fatalf("unsupported setting type %T", value)
		}
	}
	return domain.Profile{Protocol: domain.ProtocolOpenVPN, Settings: s, Secrets: secrets}
}

// mdexSettings is the RUT240 profile for mdex public.IP level 20.
func mdexSettings() map[string]any {
	return map[string]any{
		KeyRemoteHost:  "publicip20.mdex.de",
		KeyPort:        1194,
		KeyProto:       ProtoUDP,
		KeyAuthMode:    AuthModePassword,
		KeyUsername:    "tduser",
		KeyCACert:      testMaterial().caPEM,
		KeyCipher:      "none",
		KeyAuthDigest:  "none",
		KeyCompression: CompressionNone,
		KeyExtraOptions: []string{
			"tun-mtu 1500", "fragment 1448", "mssfix", "float", "nobind", "reneg-sec 86400",
			"remote-cert-tls server", "tls-version-min 1.2", "explicit-exit-notify 2", "fast-io",
			"redirect-gateway def1",
		},
	}
}

func mdexSecrets() vpn.Secrets {
	return vpn.Secrets{SecretPassword: "mdex-password"}
}

// validationFields returns the field keys of a *domain.ValidationError.
func validationFields(t *testing.T, err error) map[string]string {
	t.Helper()
	var v *domain.ValidationError
	if !errors.As(err, &v) {
		t.Fatalf("error %v is not a *domain.ValidationError", err)
	}
	return v.Fields
}

func warningCodes(warnings []Warning) []string {
	codes := make([]string, 0, len(warnings))
	for _, w := range warnings {
		codes = append(codes, w.Directive+":"+w.Code)
	}
	return codes
}
