package openvpn

import (
	"slices"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
)

// TestImportMdexFixedIP30 imports a synthetic copy of the mdex fixed.IP
// level 30 router profile: AEAD data channel, auth none, TLS 1.3, no
// client certificate and only a commented-out credentials template.
func TestImportMdexFixedIP30(t *testing.T) {
	text := unredact(readTestdata(t, "mdex_fixed_ip30.ovpn"))
	result, err := ImportOVPN(text)
	if err != nil {
		t.Fatalf("ImportOVPN: %v", err)
	}
	assertSettings(t, result.Settings, map[string]any{
		KeyRemoteHost: "openvpn30.mdex.de", KeyPort: 1194, KeyProto: ProtoUDP,
		KeyCACert: testMaterial().caPEM, KeyCipher: "CHACHA20-POLY1305:AES-256-GCM", KeyAuthDigest: "none",
		KeyResolveRetry: "infinite", KeyVerifyServerCertUsage: true, KeyAuthMode: AuthModePassword,
	})
	extras, _ := result.Settings.StringList(KeyExtraOptions)
	if want := []string{"float", "tls-version-min 1.3", "explicit-exit-notify 2"}; !slices.Equal(extras, want) {
		t.Errorf("extras = %q, want %q", extras, want)
	}
	if want := []string{KeyUsername, SecretPassword}; !slices.Equal(result.Missing, want) {
		t.Errorf("missing = %v, want %v", result.Missing, want)
	}
	assertMdexWarnings(t, result.Warnings, lineOf(text, ";<auth-user-pass>"))

	if codes := advisoryCodes(Advise(domain.PublicProfile{Settings: result.Settings})); !slices.Equal(codes, []string{AdvisoryNoDCO}) {
		t.Errorf("advisories = %v, want only %s", codes, AdvisoryNoDCO)
	}

	result.Settings.SetString(KeyUsername, credentials.username)
	result.Secrets[SecretPassword] = credentials.password
	p := domain.Profile{Protocol: domain.ProtocolOpenVPN, Settings: result.Settings, Secrets: result.Secrets}
	if err := Validate(p); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	config, _, err := Render(p, result.Secrets, testOptions)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	assertMdexConfig(t, config)
	assertGolden(t, "import_mdex_fixed_ip30.golden", redact(t, config))
}

func assertMdexWarnings(t *testing.T, warnings []Warning, templateLine int) {
	t.Helper()
	want := []Warning{
		{Code: CodeDuplicateDirective, Severity: SeverityInfo, Directive: "client", Line: 6},
		{Code: CodeDuplicateDirective, Severity: SeverityInfo, Directive: "pull", Line: 7},
		{Code: CodeDuplicateDirective, Severity: SeverityInfo, Directive: "tls-client", Line: 8},
		{Code: CodeVerbReplaced, Severity: SeverityInfo, Directive: "verb", Line: 13},
		{Code: CodeDuplicateDirective, Severity: SeverityInfo, Directive: "nobind", Line: 15},
		{Code: CodeScriptSecurityDropped, Severity: SeverityWarning, Directive: "script-security", Line: 20},
		{Code: CodeCredentialsExpected, Severity: SeverityInfo, Line: templateLine},
	}
	got := make([]Warning, len(warnings))
	for i, w := range warnings {
		w.Message = ""
		got[i] = w
	}
	if !slices.Equal(got, want) {
		t.Errorf("warnings =\n%+v\nwant\n%+v", got, want)
	}
}

func assertMdexConfig(t *testing.T, config string) {
	t.Helper()
	lines := strings.Split(config, "\n")
	for _, line := range []string{"data-ciphers CHACHA20-POLY1305:AES-256-GCM", "tls-version-min 1.3", "auth-user-pass", "auth none"} {
		if n := countLines(lines, line); n != 1 {
			t.Errorf("config has %q %d times, want once", line, n)
		}
	}
	for _, line := range []string{"tls-version-min 1.2", "script-security 2", "verb 5"} {
		if slices.Contains(lines, line) {
			t.Errorf("config contains %q", line)
		}
	}
}

func countLines(lines []string, line string) int {
	n := 0
	for _, l := range lines {
		if l == line {
			n++
		}
	}
	return n
}

// TestImportExpectsCredentials covers files without any client identity:
// the password sign-in is selected and an info note says that the file
// lacks the credentials. A commented-out <auth-user-pass> block only
// points the note at its line; its content is never imported.
func TestImportExpectsCredentials(t *testing.T) {
	m := testMaterial()
	inline := func(tag, body string) string { return "<" + tag + ">\n" + body + "</" + tag + ">\n" }
	const remote = "remote h.example\nremote-cert-tls server\n"
	tests := []struct {
		name     string
		text     string
		wantMode string
		wantNote bool
		wantLine int
	}{
		{name: "no identity", text: remote, wantMode: AuthModePassword, wantNote: true},
		{
			name: "semicolon template", text: remote + ";<auth-user-pass>\n;alice\n;secret\n;</auth-user-pass>\n",
			wantMode: AuthModePassword, wantNote: true, wantLine: 3,
		},
		{
			name: "hash template with spaces", text: remote + "  # <auth-user-pass>\n# alice\n# secret\n# </auth-user-pass>\n",
			wantMode: AuthModePassword, wantNote: true, wantLine: 3,
		},
		{name: "commented directive is no template", text: remote + "# auth-user-pass\n", wantMode: AuthModePassword, wantNote: true},
		{name: "auth-user-pass", text: remote + "auth-user-pass\n", wantMode: AuthModePassword},
		{name: "credentials file", text: remote + "auth-user-pass login.txt\n", wantMode: AuthModePassword},
		{name: "inline certificate", text: remote + inline("cert", m.clientCertPEM) + inline("key", m.clientKeyPEM), wantMode: AuthModeCertificate},
		{name: "pkcs12 file", text: remote + "pkcs12 client.p12\n", wantMode: AuthModeCertificate},
		{name: "static key", text: remote + "secret static.key\n", wantMode: AuthModePassword},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ImportOVPN(tt.text)
			if err != nil {
				t.Fatalf("ImportOVPN: %v", err)
			}
			assertSettings(t, result.Settings, map[string]any{KeyAuthMode: tt.wantMode})
			i := slices.IndexFunc(result.Warnings, func(w Warning) bool { return w.Code == CodeCredentialsExpected })
			if (i >= 0) != tt.wantNote {
				t.Fatalf("credentials_expected present = %v, want %v (%v)", i >= 0, tt.wantNote, warningCodes(result.Warnings))
			}
			if i >= 0 && (result.Warnings[i].Severity != SeverityInfo || result.Warnings[i].Line != tt.wantLine) {
				t.Errorf("note = %+v, want severity info, line %d", result.Warnings[i], tt.wantLine)
			}
			if result.Settings.Has(KeyUsername) || result.Secrets[SecretPassword] != "" {
				t.Error("credentials were imported from a comment")
			}
		})
	}
}

// lineOf returns the 1-based number of the first line of text equal to
// line, or 0.
func lineOf(text, line string) int {
	return slices.Index(strings.Split(text, "\n"), line) + 1
}
