package openvpn

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
)

const (
	partialUser     = "field-user"
	partialPassword = "field pass;word"
)

// TestImportPartialCredentialsBlock covers provider templates in which the
// user removed the comment characters of some lines only: the uncommented
// lines between opener and closer are username and password, never
// directives or extra options.
func TestImportPartialCredentialsBlock(t *testing.T) {
	const remote = "remote h.example\nremote-cert-tls server\n"
	tests := []struct {
		name         string
		block        string
		wantUser     string
		wantPassword string
	}{
		{
			name:     "data lines uncommented",
			block:    ";<auth-user-pass>\n" + partialUser + "\n" + partialPassword + "\n;</auth-user-pass>\n",
			wantUser: partialUser, wantPassword: partialPassword,
		},
		{
			name:     "hash comments and template lines kept",
			block:    "# <auth-user-pass>\n#Username\n" + partialUser + "\n#Password\n" + partialPassword + "\n# </auth-user-pass>\n",
			wantUser: partialUser, wantPassword: partialPassword,
		},
		{
			name:     "only the opener uncommented",
			block:    "<auth-user-pass>\n" + partialUser + "\n" + partialPassword + "\n;</auth-user-pass>\n",
			wantUser: partialUser, wantPassword: partialPassword,
		},
		{
			name:     "only the closer uncommented",
			block:    ";<auth-user-pass>\n" + partialUser + "\n" + partialPassword + "\n</auth-user-pass>\n",
			wantUser: partialUser, wantPassword: partialPassword,
		},
		{
			name:     "username only",
			block:    ";<auth-user-pass>\n" + partialUser + "\n;Password\n;</auth-user-pass>\n",
			wantUser: partialUser,
		},
		{
			name:  "closer uncommented without data",
			block: ";<auth-user-pass>\n;Username\n;Password\n</auth-user-pass>\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ImportOVPN(remote + tt.block)
			if err != nil {
				t.Fatalf("ImportOVPN: %v", err)
			}
			if got, _ := result.Settings.String(KeyUsername); got != tt.wantUser {
				t.Errorf("username = %q, want %q", got, tt.wantUser)
			}
			if got := result.Secrets[SecretPassword]; got != tt.wantPassword {
				t.Errorf("password = %q, want %q", got, tt.wantPassword)
			}
			if extras, _ := result.Settings.StringList(KeyExtraOptions); len(extras) != 0 {
				t.Errorf("extra options = %q, want none", extras)
			}
			want := []string{"auth-user-pass:" + CodeCredentialsFromPartialBlock}
			if got := warningCodes(result.Warnings); !slices.Equal(got, want) {
				t.Errorf("warnings = %v, want %v", got, want)
			}
			assertWarningAt(t, result.Warnings, CodeCredentialsFromPartialBlock, SeverityInfo, 3)
			assertSettings(t, result.Settings, map[string]any{KeyAuthMode: AuthModePassword})
		})
	}
}

// TestImportPartialCredentialsBlockTooManyLines fails instead of guessing
// which of the uncommented lines are the credentials, and never echoes them.
func TestImportPartialCredentialsBlockTooManyLines(t *testing.T) {
	text := "remote h.example\n;<auth-user-pass>\n" + partialUser + "\n" + partialPassword + "\nthird-line\n;</auth-user-pass>\n"
	_, err := ImportOVPN(text)
	var v *domain.ValidationError
	if !errors.As(err, &v) {
		t.Fatalf("error = %v, want a *domain.ValidationError", err)
	}
	issue := v.Issues[importField]
	if issue.Code != "openvpn_credentials_block_ambiguous" || issue.Params["line"] != "2" {
		t.Errorf("issue = %+v, want openvpn_credentials_block_ambiguous at line 2", issue)
	}
	for _, value := range []string{partialUser, partialPassword, "third-line"} {
		if strings.Contains(err.Error(), value) {
			t.Errorf("error %q echoes %q", err, value)
		}
	}
}

// TestImportFullyCommentedTemplateStaysATemplate keeps the existing rule:
// without uncommented lines the block is only a hint.
func TestImportFullyCommentedTemplateStaysATemplate(t *testing.T) {
	result, err := ImportOVPN("remote h.example\n;<auth-user-pass>\n;" + partialUser + "\n;</auth-user-pass>\n")
	if err != nil {
		t.Fatalf("ImportOVPN: %v", err)
	}
	if result.Settings.Has(KeyUsername) {
		t.Error("username imported from a comment")
	}
	assertWarningAt(t, result.Warnings, CodeCredentialsExpected, SeverityInfo, 2)
}

// TestImportUnknownDirective rejects lines that are no known OpenVPN
// directive; they never become extra options.
func TestImportUnknownDirective(t *testing.T) {
	result, err := ImportOVPN("remote h.example\nfloat\nfrobnicate 1\n")
	if err != nil {
		t.Fatalf("ImportOVPN: %v", err)
	}
	extras, _ := result.Settings.StringList(KeyExtraOptions)
	if !slices.Equal(extras, []string{"float"}) {
		t.Errorf("extra options = %q, want only float", extras)
	}
	assertWarningAt(t, result.Warnings, CodeUnknownDirective, SeverityRejected, 3)
}

// TestImportWarningsHideCredentials checks that a warning never quotes the
// imported username or password, whether as a directive or a file name.
func TestImportWarningsHideCredentials(t *testing.T) {
	text := "remote h.example\n" + partialUser + "\nfield\nauth-user-pass " + partialUser + "\n" +
		"<auth-user-pass>\n" + partialUser + "\n" + partialPassword + "\n</auth-user-pass>\n"
	result, err := ImportOVPN(text)
	if err != nil {
		t.Fatalf("ImportOVPN: %v", err)
	}
	for _, w := range result.Warnings {
		for _, value := range []string{partialUser, partialPassword, "field"} {
			if strings.Contains(w.Directive+w.File+w.Message, value) {
				t.Errorf("warning %+v quotes %q", w, value)
			}
		}
	}
	hidden := 0
	for _, w := range result.Warnings {
		if w.Directive == hiddenValue || w.File == hiddenValue {
			hidden++
		}
	}
	if hidden != 3 {
		t.Errorf("%d warnings hide a value, want 3: %+v", hidden, result.Warnings)
	}
}

// TestImportMdexWithPartialCredentials imports the mdex fixture after the
// edit that caused the field bug: only the semicolons of the two data
// lines were removed. The credentials become username and password, go
// over management and never into the rendered file, which equals the
// golden file of the untouched fixture.
func TestImportMdexWithPartialCredentials(t *testing.T) {
	text := strings.NewReplacer(";Username\n", partialUser+"\n", ";Password\n", partialPassword+"\n").
		Replace(unredact(readTestdata(t, "mdex_fixed_ip30.ovpn")))
	result, err := ImportOVPN(text)
	if err != nil {
		t.Fatalf("ImportOVPN: %v", err)
	}
	if got, _ := result.Settings.String(KeyUsername); got != partialUser || result.Secrets[SecretPassword] != partialPassword {
		t.Fatalf("credentials = %q / %q, want the uncommented lines", got, result.Secrets[SecretPassword])
	}
	if len(result.Missing) != 0 {
		t.Errorf("missing = %v, want none", result.Missing)
	}
	assertWarningAt(t, result.Warnings, CodeCredentialsFromPartialBlock, SeverityInfo, lineOf(text, ";<auth-user-pass>"))
	p := domain.Profile{Protocol: domain.ProtocolOpenVPN, Settings: result.Settings, Secrets: result.Secrets}
	if err := Validate(p); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	config, _, err := Render(p, result.Secrets, testOptions)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, value := range []string{partialUser, "field pass"} {
		if strings.Contains(config, value) {
			t.Errorf("rendered config contains %q", value)
		}
	}
	assertGolden(t, "import_mdex_fixed_ip30.golden", redact(t, config))
}

func assertWarningAt(t *testing.T, warnings []Warning, code string, severity Severity, line int) {
	t.Helper()
	i := slices.IndexFunc(warnings, func(w Warning) bool { return w.Code == code })
	if i < 0 {
		t.Fatalf("no %s warning in %v", code, warningCodes(warnings))
	}
	if warnings[i].Severity != severity || warnings[i].Line != line {
		t.Errorf("%s warning = %+v, want severity %s on line %d", code, warnings[i], severity, line)
	}
}
