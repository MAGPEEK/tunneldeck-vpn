package ipsec

import (
	"testing"

	"tunneldeck/internal/domain"
)

func TestLogLine(t *testing.T) {
	tests := []struct {
		raw       string
		wantLevel domain.LogLevel
		wantText  string
	}{
		{"00[DMN] Starting IKE charon daemon (strongSwan 6.0.7)", domain.LogLevelInfo, "[DMN] Starting IKE charon daemon (strongSwan 6.0.7)"},
		{"12[NET] sending packet: from 192.168.1.10[41234] to 198.51.100.7[500] (464 bytes)", domain.LogLevelDebug,
			"[NET] sending packet: from 192.168.1.10[41234] to 198.51.100.7[500] (464 bytes)"},
		{"12[ENC] parsing IKE_SA_INIT response 0 [ SA KE No ]", domain.LogLevelDebug, "[ENC] parsing IKE_SA_INIT response 0 [ SA KE No ]"},
		{"07[IKE] received AUTHENTICATION_FAILED notify error", domain.LogLevelWarn, "[IKE] received AUTHENTICATION_FAILED notify error"},
		{"07[IKE] establishing CHILD_SA tunneldeck{1} failed", domain.LogLevelWarn, "[IKE] establishing CHILD_SA tunneldeck{1} failed"},
		{"a line without a group", domain.LogLevelInfo, "a line without a group"},
	}
	for _, tt := range tests {
		level, text := logLine(tt.raw)
		if level != tt.wantLevel || text != tt.wantText {
			t.Errorf("logLine(%q) = %s %q, want %s %q", tt.raw, level, text, tt.wantLevel, tt.wantText)
		}
	}
}

func TestLogFailure(t *testing.T) {
	tests := map[string]domain.ErrorCode{
		"09[IKE] XAuth authentication of 'alice' (myself) failed":     domain.ErrorCodeAuthFailed,
		"09[IKE] XAuth authentication of 'alice' (myself) successful": "",
		"09[IKE] XAuth authentication of 'bob' failed":                "",
		"XAuth authentication of 'alice' (myself) failed":             "",
		"12[IKE] received AUTHENTICATION_FAILED error notify":         domain.ErrorCodeAuthFailed,
		"12[IKE] received NO_PROPOSAL_CHOSEN error notify":            domain.ErrorCodeProposalMismatch,
		"12[IKE] received AUTHENTICATION_FAILED notify error":         "",
	}
	for line, want := range tests {
		f, ok := logFailure(line)
		if f.code != want || ok != (want != "") {
			t.Errorf("logFailure(%q) = %+v, %v; want %q", line, f, ok, want)
		}
	}
}

func TestTunDevice(t *testing.T) {
	tests := []struct {
		raw    string
		want   string
		wantOK bool
	}{
		{"00[LIB] created TUN device: ipsec0", "ipsec0", true},
		{"00[LIB] created TUN device: ipsec1", "ipsec1", true},
		{"00[KNL] failed to create TUN device", "", false},
		{"created TUN device: ipsec0", "", false},
	}
	for _, tt := range tests {
		if got, ok := tunDevice(tt.raw); got != tt.want || ok != tt.wantOK {
			t.Errorf("tunDevice(%q) = %q, %v", tt.raw, got, ok)
		}
	}
}
