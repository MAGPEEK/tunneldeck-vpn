package openvpn

import (
	"errors"
	"slices"
	"testing"
)

func TestTokenize(t *testing.T) {
	tests := []struct {
		line    string
		want    []string
		wantErr error
	}{
		{line: "tun-mtu 1500", want: []string{"tun-mtu", "1500"}},
		{line: "  \tremote  host\t1194  ", want: []string{"remote", "host", "1194"}},
		{line: `verify-x509-name "vpn server" name`, want: []string{"verify-x509-name", "vpn server", "name"}},
		{line: `x "a\"b\\c"`, want: []string{"x", `a"b\c`}},
		{line: `x 'a\b "c"'`, want: []string{"x", `a\b "c"`}},
		{line: `x a\ b`, want: []string{"x", "a b"}},
		{line: `x ""`, want: []string{"x", ""}},
		{line: `x "a"b`, want: []string{"x", "a", "b"}},
		{line: `x \"a`, want: nil, wantErr: errUnterminatedQuote},
		{line: "# up /bin/sh", want: nil},
		{line: "; up /bin/sh", want: nil},
		{line: `\# up`, want: nil},
		{line: "tun-mtu 1500 # up /bin/sh", want: []string{"tun-mtu", "1500"}},
		{line: "tun-mtu 1500 ;up", want: []string{"tun-mtu", "1500"}},
		{line: "x bar#baz a;b", want: []string{"x", "bar#baz", "a;b"}},
		{line: `x "#not a comment"`, want: []string{"x", "#not a comment"}},
		{line: `x "open`, wantErr: errUnterminatedQuote},
		{line: `x 'open`, wantErr: errUnterminatedQuote},
		{line: `x a\b`, wantErr: errBadBackslash},
		{line: `x "a\b"`, wantErr: errBadBackslash},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			got, err := tokenize(tt.line)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("tokens = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestQuote(t *testing.T) {
	tests := map[string]string{
		"1500":             "1500",
		"none:AES-256-GCM": "none:AES-256-GCM",
		"/run/x.sock":      "/run/x.sock",
		"":                 `""`,
		"vpn server":       `"vpn server"`,
		"#name":            `"#name"`,
		";name":            `";name"`,
		`a"b\c`:            `"a\"b\\c"`,
		"<ca>":             `"<ca>"`,
		"'x'":              `"'x'"`,
		"ä":                "\"ä\"",
	}
	for token, want := range tests {
		if got := quote(token); got != want {
			t.Errorf("quote(%q) = %s, want %s", token, got, want)
		}
	}
}

func TestParseDirectiveStripsDoubleDash(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{line: "--up /bin/sh", want: "up"},
		{line: "----up", want: "--up"},
		{line: "--", want: "--"},
		{line: "up", want: "up"},
	}
	for _, tt := range tests {
		d, ok, err := parseDirective(tt.line)
		if err != nil || !ok || d.name != tt.want {
			t.Errorf("parseDirective(%q) = %q, %v, %v; want %q", tt.line, d.name, ok, err, tt.want)
		}
	}
}

// FuzzQuoteRoundTrip checks that every token without control characters
// survives quote and tokenize unchanged, so rendered parameters can never
// split, merge or turn into comments.
func FuzzQuoteRoundTrip(f *testing.F) {
	for _, seed := range []string{"", "a", "a b", `"`, `\`, "#", ";x", "'", `\"`, "<ca>", "ä \t x"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, token string) {
		if hasControlCharacter(token) {
			t.Skip()
		}
		line := directive{name: "x", args: []string{token}}.String()
		got, err := tokenize(line)
		if err != nil {
			t.Fatalf("tokenize(%q): %v", line, err)
		}
		if !slices.Equal(got, []string{"x", token}) {
			t.Fatalf("tokenize(%q) = %q, want [x %q]", line, got, token)
		}
	})
}
