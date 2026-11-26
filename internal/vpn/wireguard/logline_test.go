package wireguard

import (
	"strings"
	"testing"

	"tunneldeck/internal/domain"
)

func TestVerboseLine(t *testing.T) {
	tests := []struct {
		text  string
		level domain.LogLevel // "" = dropped
	}{
		{"peer(hPj9…lyE=) - Sending keepalive packet", ""},
		{"peer(hPj9…lyE=) - Receiving keepalive packet", ""},
		{"Routine: encryption worker 3 - started", ""},
		{"peer(hPj9…lyE=) - Sending handshake initiation", domain.LogLevelDebug},
		{"peer(hPj9…lyE=) - Received handshake response", domain.LogLevelDebug},
		{"peer(hPj9…lyE=) - Handshake did not complete after 5 seconds, retrying (try 2)", domain.LogLevelDebug},
		{"UAPI: Updating private key", domain.LogLevelDebug},
		{"peer(hPj9…lyE=) - UAPI: Created", domain.LogLevelDebug},
		{"Interface state was Down, requested Up, now Up", domain.LogLevelInfo},
		{"peer(hPj9…lyE=) - Handshake did not complete after 20 attempts, giving up", domain.LogLevelInfo},
		{"peer(hPj9…lyE=) - Retrying handshake because we stopped hearing back after 15 seconds", domain.LogLevelInfo},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			level, text, keep := verboseLine(tt.text)
			if keep != (tt.level != "") || level != tt.level {
				t.Fatalf("verboseLine = %q, %v; want %q", level, keep, tt.level)
			}
			if keep && text != tt.text {
				t.Errorf("text = %q", text)
			}
		})
	}
}

func TestLogLinesHideKeys(t *testing.T) {
	line := `IPC error 2: failed to parse line "private_key=` + rfcPrivateHex + `"`
	level, text := errorLine(line)
	if level != domain.LogLevelError || strings.Contains(text, rfcPrivateHex) || !strings.Contains(text, "(hidden)") {
		t.Errorf("errorLine = %q, %q", level, text)
	}
	if _, text, _ := verboseLine("UAPI: " + rfcPublicHex); strings.Contains(text, rfcPublicHex) {
		t.Errorf("verboseLine = %q", text)
	}
}
