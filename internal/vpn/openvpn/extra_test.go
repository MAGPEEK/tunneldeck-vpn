package openvpn

import (
	"strings"
	"testing"
)

// outcome of one extra option: the canonical line when kept, else the
// warning code and whether it fails validation.
type extraOutcome struct {
	kept     string
	code     string
	rejected bool
}

func checkOne(line string) (extraOutcome, bool) {
	result := checkExtraOptions([]string{line})
	switch {
	case len(result.kept) == 1:
		return extraOutcome{kept: result.kept[0].directive.String()}, true
	case len(result.rejected) == 1:
		return extraOutcome{code: result.rejected[0].Code, rejected: true}, true
	case len(result.dropped) == 1:
		return extraOutcome{code: result.dropped[0].Code}, true
	}
	return extraOutcome{}, false
}

func kept(line string) extraOutcome     { return extraOutcome{kept: line} }
func rejected(code string) extraOutcome { return extraOutcome{code: code, rejected: true} }
func dropped(code string) extraOutcome  { return extraOutcome{code: code} }

// TestExtraOptionsHostile feeds directives that would run code, escape the
// sandbox, inject inline blocks or hide behind comments and quoting.
func TestExtraOptionsHostile(t *testing.T) {
	tests := []struct {
		line string
		want extraOutcome
	}{
		// script directives in every spelling
		{"up /bin/sh", rejected(CodeRunsCode)},
		{"--up /bin/sh", rejected(CodeRunsCode)},
		{"\tup /bin/sh", rejected(CodeRunsCode)},
		{"\t\t --up /bin/sh", rejected(CodeRunsCode)},
		{`"up" /bin/sh`, rejected(CodeRunsCode)},
		{`'up' /bin/sh`, rejected(CodeRunsCode)},
		{`u\p /bin/sh`, rejected(CodeInvalidLine)},
		{"UP /bin/sh", rejected(CodeInvalidDirective)},
		{"Up /bin/sh", rejected(CodeInvalidDirective)},
		{"----up /bin/sh", rejected(CodeInvalidDirective)},
		{"down /bin/sh", rejected(CodeRunsCode)},
		{"route-up /bin/sh", rejected(CodeRunsCode)},
		{"route-pre-down /bin/sh", rejected(CodeRunsCode)},
		{"ipchange /bin/sh", rejected(CodeRunsCode)},
		{"tls-verify /bin/sh", rejected(CodeRunsCode)},
		{"auth-user-pass-verify /bin/sh via-env", rejected(CodeRunsCode)},
		{"client-connect /bin/sh", rejected(CodeRunsCode)},
		{"learn-address /bin/sh", rejected(CodeRunsCode)},
		{"plugin /usr/lib/x.so", rejected(CodeRunsCode)},
		{"script-security 2", rejected(CodeRunsCode)},
		{"dns-updown /bin/sh", rejected(CodeRunsCode)},
		{"setenv opt up /bin/sh", rejected(CodeRunsCode)},
		{"setenv-safe X 1", dropped(CodeSetenvIgnored)},
		{"setenv FORWARD_COMPATIBLE 1", dropped(CodeSetenvIgnored)},
		{"up-restart", rejected(CodeRunsCode)},
		{"iproute /bin/sh", rejected(CodeRunsCode)},
		{"engine dynamic", rejected(CodeRunsCode)},
		{"providers legacy", rejected(CodeRunsCode)},
		// sandbox escapes
		{"management 0.0.0.0 7505", rejected(CodeEscapesSandbox)},
		{"management-hold", rejected(CodeEscapesSandbox)},
		{"management-client-user root", rejected(CodeEscapesSandbox)},
		{"daemon", rejected(CodeEscapesSandbox)},
		{"log /data/secret.key", rejected(CodeEscapesSandbox)},
		{"log-append /tmp/x", rejected(CodeEscapesSandbox)},
		{"status /tmp/x", rejected(CodeEscapesSandbox)},
		{"writepid /tmp/x", rejected(CodeEscapesSandbox)},
		{"config /etc/openvpn/evil.conf", rejected(CodeEscapesSandbox)},
		{"cd /", rejected(CodeEscapesSandbox)},
		{"chroot /tmp", rejected(CodeEscapesSandbox)},
		{"dev tap0", rejected(CodeEscapesSandbox)},
		{"dev-type tap", rejected(CodeEscapesSandbox)},
		{"dev-node /dev/net/tun", rejected(CodeEscapesSandbox)},
		{"tls-export-cert /tmp", rejected(CodeEscapesSandbox)},
		{"pkcs12 /data/x.p12", rejected(CodeEscapesSandbox)},
		{"pkcs12 [inline]", rejected(CodeEscapesSandbox)},
		// static-key mode (SPEC §17)
		{"secret /data/static.key", rejected(CodeStaticKeyUnsupported)},
		{"crl-verify /etc/crl.pem", rejected(CodeEscapesSandbox)},
		// inline-block injection and line breaks
		{"<ca>", rejected(CodeInlineBlock)},
		{"</ca>", rejected(CodeInlineBlock)},
		{"<connection>", rejected(CodeInlineBlock)},
		{"tun-mtu 1500\nup /bin/sh", rejected(CodeInvalidLine)},
		{"tun-mtu 1500\rup /bin/sh", rejected(CodeInvalidLine)},
		{"tun-mtu 1500\x00up /bin/sh", rejected(CodeInvalidLine)},
		{"tun-mtu \"1500\n</ca>\"", rejected(CodeInvalidLine)},
		{"tun-mtu 1500\r", kept("tun-mtu 1500")},
		{"tun-mtu \"1500", rejected(CodeInvalidLine)},
		// comment tricks
		{"# up /bin/sh", extraOutcome{}},
		{"; up /bin/sh", extraOutcome{}},
		{"tun-mtu 1500 # up /bin/sh", kept("tun-mtu 1500")},
		{"tun-mtu 1500 ; up /bin/sh", kept("tun-mtu 1500")},
		{`verify-x509-name "#name" name`, kept(`verify-x509-name "#name" name`)},
		{`verify-x509-name ';x' name`, kept(`verify-x509-name ";x" name`)},
		{`verify-x509-name "a\"b" name`, kept(`verify-x509-name "a\"b" name`)},
		// overlong lines
		{"verify-x509-name " + strings.Repeat("a", 254-len("verify-x509-name ")), kept("verify-x509-name " + strings.Repeat("a", 254-len("verify-x509-name ")))},
		{"verify-x509-name " + strings.Repeat("a", 255-len("verify-x509-name ")), rejected(CodeLineTooLong)},
		{"verify-x509-name '" + strings.Repeat("\"", 200) + "'", rejected(CodeLineTooLong)},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			got, _ := checkOne(tt.line)
			if got != tt.want {
				t.Errorf("outcome = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestExtraOptionsHandledByTunnelDeck(t *testing.T) {
	tests := []struct {
		line string
		want extraOutcome
	}{
		{"redirect-gateway def1", dropped(CodeRoutingHandled)},
		{"redirect-private local", dropped(CodeRoutingHandled)},
		{"route 10.0.0.0 255.0.0.0", dropped(CodeRoutingHandled)},
		{"route-ipv6 ::/0", dropped(CodeRoutingHandled)},
		{"route-noexec", dropped(CodeRoutingHandled)},
		{"route-nopull", dropped(CodeRoutingHandled)},
		{"ifconfig-noexec", dropped(CodeRoutingHandled)},
		{`pull-filter accept "route"`, dropped(CodeRoutingHandled)},
		{"client", dropped(CodeDuplicateDirective)},
		{"pull", dropped(CodeDuplicateDirective)},
		{"tls-client", dropped(CodeDuplicateDirective)},
		{"nobind", dropped(CodeDuplicateDirective)},
		{"persist-tun", dropped(CodeDuplicateDirective)},
		{"disable-dco", dropped(CodeDuplicateDirective)},
		{"auth-retry nointeract", dropped(CodeDuplicateDirective)},
		{"verb 9", dropped(CodeDuplicateDirective)},
		{"remote evil.example 1194", dropped(CodeManagedByField)},
		{"proto tcp", dropped(CodeManagedByField)},
		{"port 1", dropped(CodeManagedByField)},
		{"ca /etc/ca.pem", dropped(CodeManagedByField)},
		{"cert c.pem", dropped(CodeManagedByField)},
		{"key k.pem", dropped(CodeManagedByField)},
		{"tls-auth ta.key 1", dropped(CodeManagedByField)},
		{"tls-crypt tc.key", dropped(CodeManagedByField)},
		{"tls-crypt-v2 tc2.key", dropped(CodeManagedByField)},
		{"cipher AES-256-CBC", dropped(CodeManagedByField)},
		{"data-ciphers AES-256-GCM", dropped(CodeManagedByField)},
		{"data-ciphers-fallback none", dropped(CodeManagedByField)},
		{"auth SHA1", dropped(CodeManagedByField)},
		{"comp-lzo no", dropped(CodeManagedByField)},
		{"compress lzo", dropped(CodeManagedByField)},
		{"auth-user-pass /etc/creds", dropped(CodeManagedByField)},
		{"remote-cert-tls server", dropped(CodeManagedByField)},
		{"ns-cert-type server", dropped(CodeManagedByField)},
		{"fast-io", dropped(CodeDeprecatedIgnored)},
		{"persist-key", dropped(CodeDeprecatedIgnored)},
		{"comp-noadapt", dropped(CodeDeprecatedIgnored)},
		{"compress lz4-v2", kept("compress lz4-v2")},
		{"push-peer-info", kept("push-peer-info")},
		{"explicit-exit-notify 2", kept("explicit-exit-notify 2")},
		{"fragment 1448", kept("fragment 1448")},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			got, _ := checkOne(tt.line)
			if got != tt.want {
				t.Errorf("outcome = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestCheckExtraOptionsKeepsOrderAndLineNumbers(t *testing.T) {
	result := checkExtraOptions([]string{"float", "", "up x", "fast-io", "mssfix"})
	if len(result.kept) != 2 || result.kept[0].line != 1 || result.kept[1].line != 5 {
		t.Errorf("kept = %+v, want float at 1 and mssfix at 5", result.kept)
	}
	if len(result.rejected) != 1 || result.rejected[0].Line != 3 || result.rejected[0].Directive != "up" {
		t.Errorf("rejected = %+v, want up at line 3", result.rejected)
	}
	if len(result.dropped) != 1 || result.dropped[0].Line != 4 {
		t.Errorf("dropped = %+v, want fast-io at line 4", result.dropped)
	}
}

func TestDescribeRejectionsNeverEchoesInvalidText(t *testing.T) {
	result := checkExtraOptions([]string{"up /bin/sh", "Secret-Value x", "a \"b"})
	message := describeRejections(result.rejected)
	want := `line 1: "up" runs a script, plugin or external program and is not allowed; ` +
		"line 2: is not a valid OpenVPN directive name; line 3: cannot be parsed: unterminated quote"
	if message != want {
		t.Errorf("message = %q\nwant %q", message, want)
	}
}
