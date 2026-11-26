package openvpn

import (
	"crypto/rand"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
)

// TestImportRealisticProfiles imports synthetic profiles shaped like those
// of common servers and providers, renders them after the user filled in
// what the import reports as missing, and compares with golden files.
func TestImportRealisticProfiles(t *testing.T) {
	tests := []struct {
		name         string
		file         string
		golden       string
		transform    func(string) string
		wantWarnings []string
		wantMissing  []string
		wantSettings map[string]any
	}{
		{
			name: "access server", file: "access_server.ovpn", golden: "import_access_server.golden",
			wantWarnings: accessServerWarnings,
			wantMissing:  []string{KeyUsername, SecretPassword},
			wantSettings: map[string]any{
				KeyRemoteHost: "vpn.example.com", KeyPort: 1194, KeyProto: ProtoUDP,
				KeyAuthMode: AuthModeCertificateAndPassword,
			},
		},
		{
			name: "access server with BOM, CRLF, Latin-1 comment and long comment",
			file: "access_server.ovpn", golden: "import_access_server.golden",
			transform: func(text string) string {
				text = "# Profil f\xfcr das B\xfcro\n# " + strings.Repeat("x", 600) + "\n" + text
				return utf8BOM + strings.ReplaceAll(text, "\n", "\r\n")
			},
			wantWarnings: accessServerWarnings,
			wantMissing:  []string{KeyUsername, SecretPassword},
		},
		{
			name: "cloud service", file: "cloudconnexa.ovpn", golden: "import_cloudconnexa.golden",
			wantWarnings: []string{
				"client:duplicate_directive", "remote:additional_remote", "nobind:duplicate_directive",
				"verb:duplicate_directive", "pull-filter:routing_handled",
			},
			wantMissing: []string{},
			wantSettings: map[string]any{
				KeyRemoteHost: "region-a.example.net", KeyPort: 1194, KeyAuthMode: AuthModeCertificate,
				KeyCipher: "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", KeyKeepalive: "10 60",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text := unredact(readTestdata(t, tt.file))
			if tt.transform != nil {
				text = tt.transform(text)
			}
			result, err := ImportOVPN(text)
			if err != nil {
				t.Fatalf("ImportOVPN: %v", err)
			}
			if got := warningCodes(result.Warnings); !slices.Equal(got, tt.wantWarnings) {
				t.Errorf("warnings = %v, want %v", got, tt.wantWarnings)
			}
			if !slices.Equal(result.Missing, tt.wantMissing) {
				t.Errorf("missing = %v, want %v", result.Missing, tt.wantMissing)
			}
			assertSettings(t, result.Settings, tt.wantSettings)
			if slices.Contains(result.Missing, KeyUsername) {
				result.Settings.SetString(KeyUsername, credentials.username)
				result.Secrets[SecretPassword] = credentials.password
			}
			p := domain.Profile{Protocol: domain.ProtocolOpenVPN, Settings: result.Settings, Secrets: result.Secrets}
			if err := Validate(p); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			config, _, err := Render(p, result.Secrets, testOptions)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			assertGolden(t, tt.golden, redact(t, config))
		})
	}
}

var accessServerWarnings = []string{
	"setenv:setenv_ignored", "client:duplicate_directive", "nobind:duplicate_directive",
	"remote:additional_remote", "remote:additional_remote", "verb:duplicate_directive",
	"setenv:setenv_ignored", "setenv:setenv_ignored", "pull-filter:routing_handled",
}

func TestImportProviderFileReferences(t *testing.T) {
	result, err := ImportOVPN(readTestdata(t, "provider_files.ovpn"))
	if err != nil {
		t.Fatalf("ImportOVPN: %v", err)
	}
	wantFiles := map[string]string{"ca": "ca.crt", "cert": "client.crt", "key": "client.key", "tls-auth": "ta.key"}
	for _, w := range result.Warnings {
		if w.Code != CodeFileReference {
			continue
		}
		if w.File != wantFiles[w.Directive] || w.Severity != SeverityRejected {
			t.Errorf("warning %+v, want file %q, severity rejected", w, wantFiles[w.Directive])
		}
		if !strings.Contains(w.Message, w.File) || !strings.Contains(w.Message, "<"+w.Directive+">") {
			t.Errorf("message %q names neither the file nor the inline block", w.Message)
		}
		delete(wantFiles, w.Directive)
	}
	if len(wantFiles) > 0 {
		t.Errorf("no file_reference warning for %v", wantFiles)
	}
	wantMissing := []string{KeyUsername, SecretPassword, KeyCACert, KeyClientCert, SecretClientKey, SecretTLSAuthKey}
	if !slices.Equal(result.Missing, wantMissing) {
		t.Errorf("missing = %v, want %v", result.Missing, wantMissing)
	}
	assertSettings(t, result.Settings, map[string]any{
		KeyRemoteHost: "203.0.113.10", KeyAuthMode: AuthModeCertificateAndPassword,
		KeyKeyDirection: KeyDirectionNormal, KeyCipher: "AES-256-CBC",
	})
}

func TestImportMissingFields(t *testing.T) {
	m := testMaterial()
	inline := func(tag, body string) string { return "<" + tag + ">\n" + body + "</" + tag + ">\n" }
	tests := []struct {
		name string
		text string
		want []string
	}{
		{name: "password sign-in without credentials", text: "remote h.example\nauth-user-pass\n", want: []string{KeyUsername, SecretPassword, KeyCACert}},
		{
			name: "inline credentials and CA",
			text: "remote h.example\n" + inline("ca", m.caPEM) + "<auth-user-pass>\nalice\nsecret\n</auth-user-pass>\n",
			want: []string{},
		},
		{
			name: "certificate without key",
			text: "remote h.example\n" + inline("ca", m.caPEM) + inline("cert", m.clientCertPEM),
			want: []string{SecretClientKey},
		},
		{
			name: "encrypted key",
			text: "remote h.example\n" + inline("ca", m.caPEM) + inline("cert", m.clientCertPEM) + inline("key", encryptedKeyPEM()),
			want: []string{SecretKeyPassphrase},
		},
		{name: "pkcs12 file", text: "remote h.example\npkcs12 client.p12\n", want: []string{KeyCACert, SecretPKCS12}},
		{
			name: "tls-crypt-v2 file",
			text: "remote h.example\ntls-crypt-v2 client.key\n" + inline("ca", m.caPEM),
			want: []string{KeyUsername, SecretPassword, SecretTLSCryptV2Key},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ImportOVPN(tt.text)
			if err != nil {
				t.Fatalf("ImportOVPN: %v", err)
			}
			if !slices.Equal(result.Missing, tt.want) {
				t.Errorf("missing = %v, want %v", result.Missing, tt.want)
			}
		})
	}
}

// encryptedKeyPEM returns a PKCS#8 "ENCRYPTED PRIVATE KEY" block with
// random content; only OpenVPN decrypts it.
func encryptedKeyPEM() string {
	body := make([]byte, 200)
	if _, err := rand.Read(body); err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: pemEncryptedPrivateKey, Bytes: body}))
}

func TestImportUnusableFiles(t *testing.T) {
	tests := []struct {
		name, text, wantCode string
	}{
		{name: "empty", text: "", wantCode: "openvpn_file_empty"},
		{name: "whitespace and BOM", text: utf8BOM + " \r\n\t\r\n", wantCode: "openvpn_file_empty"},
		{name: "comments only", text: "# nothing\n; here\n", wantCode: "openvpn_file_empty"},
		{name: "plain text", text: "Dear customer,\nyour VPN is ready.\n", wantCode: "openvpn_not_a_profile"},
		{name: "json", text: `{"remote": "vpn.example.com"}`, wantCode: "openvpn_not_a_profile"},
		{name: "binary", text: "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", wantCode: "openvpn_not_a_profile"},
		{name: "unknown block only", text: "<html>\n</html>\n", wantCode: "openvpn_not_a_profile"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ImportOVPN(tt.text)
			var v *domain.ValidationError
			if !errors.As(err, &v) {
				t.Fatalf("error %v is not a *domain.ValidationError", err)
			}
			if got := v.Issues[importField].Code; got != tt.wantCode {
				t.Errorf("code = %q, want %q", got, tt.wantCode)
			}
		})
	}
}

func TestImportLongLines(t *testing.T) {
	text := "remote h.example\nremote-cert-tls server\n# " + strings.Repeat("c", 2000) + "\n" +
		"verify-x509-name " + strings.Repeat("a", 300) + " name\n"
	result, err := ImportOVPN(text)
	if err != nil {
		t.Fatalf("ImportOVPN: %v", err)
	}
	if got, want := warningCodes(result.Warnings), []string{":line_too_long"}; !slices.Equal(got, want) {
		t.Errorf("warnings = %v, want %v", got, want)
	}
}
