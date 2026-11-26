package ipsec

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func TestRenderStrongswanConf(t *testing.T) {
	assertGolden(t, "strongswan.conf.golden", renderStrongswanConf("/run/tunneldeck/ipsec/charon.vici"))
}

// TestConnectionMessage renders the load-conn request of typical profiles
// in swanctl.conf syntax. Certificates are shown by subject.
func TestConnectionMessage(t *testing.T) {
	pki := newTestPKI(t)
	tests := []struct {
		name     string
		settings map[string]any
		secrets  map[string]string
	}{
		{name: "psk_virtual_ip.golden", settings: map[string]any{KeyGateway: "vpn.example.com"}, secrets: map[string]string{SecretPSK: testPSK}},
		{
			name: "psk_net_to_net.golden",
			settings: map[string]any{
				KeyGateway: "198.51.100.7", KeyMode: "netToNet", KeyTemplate: "fritzbox",
				KeyLocalSubnets: []string{"192.168.1.0/24"}, KeyRemoteSubnets: []string{"10.20.0.0/16", "10.30.0.0/16"},
				KeyLocalID: "office.example.net", KeyRemoteID: "home.example.net",
				KeyIKEProposals: []string{"aes256-sha512-sha256-modp2048"}, KeyESPProposals: []string{"aes256-sha512-sha256-modp2048"},
			},
			secrets: map[string]string{SecretPSK: testPSK},
		},
		{
			name: "ikev1_xauth.golden",
			settings: map[string]any{
				KeyGateway: "office.example.net", KeyIKEVersion: "ikev1", KeyTemplate: "fritzboxUser", KeyXAuthUsername: "alice",
				KeyLocalID: "alice", KeyRemoteSubnets: []string{"192.168.178.0/24"},
				KeyIKEProposals: []string{"aes256-sha512-modp2048", "aes256-sha512-modp1024"}, KeyESPProposals: []string{"aes256-sha512", "aes256-sha1"},
			},
			secrets: map[string]string{SecretPSK: testPSK, SecretXAuthPassword: "xauth-password"},
		},
		{
			name: "eap.golden",
			settings: map[string]any{
				KeyGateway: "vpn.example.com", KeyAuthMethod: "eapMschapv2", KeyUsername: "alice",
				KeyCACert: pki.caPEM, KeyRemoteID: "vpn.example.com",
			},
			secrets: map[string]string{SecretEAPPassword: "alice-password"},
		},
		{
			name: "certificate.golden",
			settings: map[string]any{
				KeyGateway: "vpn.example.com", KeyAuthMethod: "certificate", KeyCACert: pki.caPEM,
				KeyClientCert: pki.clientPEM, KeyRemoteID: "CN=vpn.example.com",
			},
			secrets: map[string]string{SecretClientKey: pki.keyPEM},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := mustConfig(t, profileWith(tt.settings, tt.secrets))
			got := formatMessage(connectionMessage(c), "")
			assertGolden(t, tt.name, got)
			for _, secret := range tt.secrets {
				if strings.Contains(got, secret) {
					t.Errorf("the connection carries a secret")
				}
			}
		})
	}
}

func TestCredentialRequests(t *testing.T) {
	pki := newTestPKI(t)
	tests := []struct {
		name     string
		settings map[string]any
		secrets  map[string]string
		want     string
	}{
		{name: "psk", settings: map[string]any{KeyGateway: "vpn.example.com"}, secrets: map[string]string{SecretPSK: testPSK},
			want: "load-shared {type = IKE; data = " + testPSK + "}"},
		{
			name: "eap",
			settings: map[string]any{
				KeyGateway: "vpn.example.com", KeyAuthMethod: "eapMschapv2", KeyUsername: "alice", KeyCACert: pki.caPEM, KeyRemoteID: "vpn",
			},
			secrets: map[string]string{SecretEAPPassword: "pw"},
			want:    "load-shared {type = EAP; data = pw; owners = [alice]}",
		},
		{
			name:     "ikev1 xauth",
			settings: map[string]any{KeyGateway: "office.example.net", KeyIKEVersion: "ikev1", KeyXAuthUsername: "alice"},
			secrets:  map[string]string{SecretPSK: testPSK, SecretXAuthPassword: "xauth-password"},
			want:     "load-shared {type = IKE; data = " + testPSK + "}\nload-shared {type = XAUTH; data = xauth-password; owners = [alice]}",
		},
		{
			name: "certificate with chain",
			settings: map[string]any{
				KeyGateway: "vpn.example.com", KeyAuthMethod: "certificate", KeyCACert: pki.caPEM,
				KeyClientCert: pki.clientPEM + pki.caPEM, KeyRemoteID: "vpn",
			},
			secrets: map[string]string{SecretClientKey: pki.keyPEM},
			want:    "load-key {type = any; data = <PRIVATE KEY>}\nload-cert {type = X509; flag = NONE; data = <certificate CN=Test CA>}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var lines []string
			for _, r := range credentialRequests(mustConfig(t, profileWith(tt.settings, tt.secrets))) {
				lines = append(lines, r.command+" {"+strings.ReplaceAll(strings.TrimSpace(formatMessage(r.message, "")), "\n", "; ")+"}")
			}
			if got := strings.Join(lines, "\n"); got != tt.want {
				t.Errorf("requests\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

// formatMessage writes m in swanctl.conf syntax; PEM values are shown as
// the subject of their certificate or as the block type.
func formatMessage(m *message, indent string) string {
	var b strings.Builder
	for _, e := range m.entries {
		switch e.kind {
		case entryValue:
			b.WriteString(indent + e.key + " = " + displayValue(e.value) + "\n")
		case entryList:
			items := make([]string, len(e.list))
			for i, item := range e.list {
				items[i] = displayValue(item)
			}
			b.WriteString(indent + e.key + " = [" + strings.Join(items, ", ") + "]\n")
		case entrySection:
			b.WriteString(indent + e.key + " {\n" + formatMessage(e.section, indent+"  ") + indent + "}\n")
		}
	}
	return b.String()
}

func displayValue(value string) string {
	if !strings.HasPrefix(value, "-----BEGIN ") {
		return value
	}
	if certs, err := parseCertificates(value); err == nil {
		return "<certificate " + certs[0].Subject.String() + ">"
	}
	return "<" + strings.TrimSuffix(strings.TrimPrefix(strings.SplitN(value, "\n", 2)[0], "-----BEGIN "), "-----") + ">"
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
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if want := strings.ReplaceAll(string(b), "\r\n", "\n"); got != want {
		t.Errorf("%s differs from golden file\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}
