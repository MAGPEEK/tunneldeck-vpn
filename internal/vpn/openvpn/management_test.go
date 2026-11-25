package openvpn

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"tunneldeck/internal/domain"
)

func TestParseManagementLine(t *testing.T) {
	at := time.Unix(1795632689, 0).UTC()
	tests := []struct {
		name string
		line string
		want managementMessage
	}{
		{
			name: "info banner",
			line: ">INFO:OpenVPN Management Interface Version 6 -- type 'help' for more info",
			want: infoMessage{text: "OpenVPN Management Interface Version 6 -- type 'help' for more info"},
		},
		{name: "first hold", line: ">HOLD:Waiting for hold release:0", want: holdMessage{waitSeconds: 0}},
		{name: "hold after restart", line: ">HOLD:Waiting for hold release:10", want: holdMessage{waitSeconds: 10}},
		{name: "hold without seconds", line: ">HOLD:Waiting for hold release", want: holdMessage{}},
		{
			name: "connected",
			line: ">STATE:1795632689,CONNECTED,SUCCESS,10.66.0.2,172.20.0.2,1194,,",
			want: stateMessage{
				time: at, name: "CONNECTED", detail: "SUCCESS",
				tunnelIP: "10.66.0.2", remoteIP: "172.20.0.2", remotePort: "1194",
			},
		},
		{
			name: "reconnecting",
			line: ">STATE:1795632689,RECONNECTING,ping-restart,,,,,",
			want: stateMessage{time: at, name: "RECONNECTING", detail: "ping-restart"},
		},
		{
			name: "state with only two fields",
			line: ">STATE:1795632689,WAIT",
			want: stateMessage{time: at, name: "WAIT"},
		},
		{name: "byte count", line: ">BYTECOUNT:4172,2327", want: byteCountMessage{in: 4172, out: 2327}},
		{
			name: "log text keeps its commas",
			line: ">LOG:1795632689,I,SIGTERM received, sending exit notification to peer",
			want: logMessage{time: at, flags: "I", text: "SIGTERM received, sending exit notification to peer"},
		},
		{
			name: "log without flags",
			line: ">LOG:1795632689,,Socket Buffers: R=[212992->212992]",
			want: logMessage{time: at, flags: "", text: "Socket Buffers: R=[212992->212992]"},
		},
		{
			name: "credentials needed",
			line: ">PASSWORD:Need 'Auth' username/password",
			want: passwordMessage{kind: passwordNeeded, realm: realmAuth},
		},
		{
			name: "key passphrase needed",
			line: ">PASSWORD:Need 'Private Key' password",
			want: passwordMessage{kind: passwordNeeded, realm: realmPrivateKey},
		},
		{
			name: "credentials rejected",
			line: ">PASSWORD:Verification Failed: 'Auth'",
			want: passwordMessage{kind: passwordRejected, realm: realmAuth},
		},
		{
			name: "rejected with reason",
			line: ">PASSWORD:Verification Failed: 'Auth' ['Data channel cipher negotiation failed (no shared cipher)']",
			want: passwordMessage{
				kind: passwordRejected, realm: realmAuth,
				reason: "Data channel cipher negotiation failed (no shared cipher)", hasReason: true,
			},
		},
		{
			name: "rejected with malformed reason",
			line: ">PASSWORD:Verification Failed: 'Auth' [oops",
			want: passwordMessage{kind: passwordRejected, realm: realmAuth},
		},
		{name: "auth token is not kept", line: ">PASSWORD:Auth-Token:c2VjcmV0", want: passwordMessage{kind: passwordOther}},
		{
			name: "fatal",
			line: ">FATAL:ERROR: Cannot open TUN/TAP dev /dev/net/tun: No such file or directory (errno=2)",
			want: fatalMessage{text: "ERROR: Cannot open TUN/TAP dev /dev/net/tun: No such file or directory (errno=2)"},
		},
		{
			name: "success reply",
			line: "SUCCESS: real-time state notification set to ON",
			want: replyMessage{success: true, text: "real-time state notification set to ON"},
		},
		{
			name: "error reply",
			line: "ERROR: unknown command, enter 'help' for more options",
			want: replyMessage{success: false, text: "unknown command, enter 'help' for more options"},
		},
		{name: "unused notification", line: ">NEED-OK:Need 'token-insertion-request' confirmation", want: ignoredMessage{}},
		{name: "prefix without colon", line: ">STATE", want: ignoredMessage{}},
		{name: "end of block", line: "END", want: ignoredMessage{}},
		{name: "history line", line: "1795632743,CONNECTING,,,,,,", want: ignoredMessage{}},
		{name: "empty", line: "", want: ignoredMessage{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseManagementLine(tt.line)
			if err != nil {
				t.Fatalf("parseManagementLine: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestParseManagementLineMalformed(t *testing.T) {
	tests := []struct {
		line       string
		wantPrefix string
	}{
		{line: ">STATE:1795632689", wantPrefix: "malformed >STATE"},
		{line: ">STATE:soon,CONNECTED,SUCCESS", wantPrefix: "malformed >STATE"},
		{line: ">BYTECOUNT:4172", wantPrefix: "malformed >BYTECOUNT"},
		{line: ">BYTECOUNT:many,2327", wantPrefix: "malformed >BYTECOUNT"},
		{line: ">LOG:1795632689,I", wantPrefix: "malformed >LOG"},
		{line: ">LOG:yesterday,I,text", wantPrefix: "malformed >LOG"},
		{line: ">HOLD:Waiting for hold release:x", wantPrefix: "malformed >HOLD"},
		{line: ">PASSWORD:Need 'Auth", wantPrefix: "malformed >PASSWORD"},
		{line: ">PASSWORD:Verification Failed: 'Auth", wantPrefix: "malformed >PASSWORD"},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			_, err := parseManagementLine(tt.line)
			if err == nil || !strings.HasPrefix(err.Error(), tt.wantPrefix) {
				t.Fatalf("error = %v, want prefix %q", err, tt.wantPrefix)
			}
		})
	}
}

func TestCredentialCommandEscaping(t *testing.T) {
	tests := []struct {
		name, command, realm, value, want string
	}{
		{name: "plain", command: "username", realm: realmAuth, value: "tduser", want: `username "Auth" "tduser"`},
		{
			name: "quotes, backslashes and comment characters", command: "password", realm: realmAuth,
			value: `p a"s\s'w#rd;$x`, want: `password "Auth" "p a\"s\\s'w#rd;$x"`,
		},
		{name: "empty", command: "password", realm: realmAuth, value: "", want: `password "Auth" ""`},
		{name: "utf-8", command: "password", realm: realmPrivateKey, value: "pässwört", want: `password "Private Key" "pässwört"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := credentialCommand(tt.command, tt.realm, tt.value); got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestManagementLogLevel(t *testing.T) {
	tests := []struct {
		flags, text string
		want        domain.LogLevel
	}{
		{"W", "WARNING: cipher 'none' specified for --data-ciphers.", domain.LogLevelWarn},
		{"W", "******* WARNING *******: '--auth none' was specified.", domain.LogLevelWarn},
		{"W", "WARNING: this configuration may cache passwords in memory", domain.LogLevelWarn},
		{"N", "Options error: option 'redirect-gateway' cannot be used in this context ([PUSH-OPTIONS])", domain.LogLevelWarn},
		{"N", "VERIFY ERROR: depth=1, error=self-signed certificate in certificate chain", domain.LogLevelError},
		{"F", "Exiting due to fatal error", domain.LogLevelError},
		{"I", "Initialization Sequence Completed", domain.LogLevelInfo},
		{"", "Socket Buffers: R=[212992->212992]", domain.LogLevelInfo},
		{"D", "MANAGEMENT: CMD 'bytecount 2'", domain.LogLevelDebug},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			if got := managementLogLevel(tt.flags, tt.text); got != tt.want {
				t.Errorf("level = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestOutputLogLevel(t *testing.T) {
	tests := []struct {
		line string
		want domain.LogLevel
	}{
		{"2026-11-25 18:52:23 WARNING: cipher 'none' specified for --data-ciphers.", domain.LogLevelWarn},
		{"2026-11-25 18:52:23 DEPRECATED OPTION: --cipher set to 'none'", domain.LogLevelWarn},
		{"2026-11-25 18:52:23 Options error: You must define CA file (--ca)", domain.LogLevelError},
		{"Options error: option 'route' cannot be used in this context ([PUSH-OPTIONS])", domain.LogLevelWarn},
		{"2026-11-25 18:52:23 Exiting due to fatal error", domain.LogLevelError},
		{"2026-11-25 18:52:23 OpenVPN 2.7.9 x86_64-alpine-linux-musl", domain.LogLevelInfo},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			if got := outputLogLevel(stripOutputTimestamp(tt.line)); got != tt.want {
				t.Errorf("level = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestStripOutputTimestamp(t *testing.T) {
	got := stripOutputTimestamp("2026-11-25 18:52:23 Need hold release from management interface, waiting...")
	if want := "Need hold release from management interface, waiting..."; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := stripOutputTimestamp("no timestamp"); got != "no timestamp" {
		t.Errorf("got %q, want the line unchanged", got)
	}
}
