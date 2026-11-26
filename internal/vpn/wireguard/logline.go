package wireguard

import (
	"regexp"
	"strings"

	"tunneldeck/internal/domain"
)

// hexKey matches a key in the UAPI's hex form. wireguard-go prints UAPI
// lines only in parse errors, but such a line could hold a private key.
var hexKey = regexp.MustCompile(`[0-9a-fA-F]{64}`)

// droppedLines mark verbose lines of wireguard-go that are left out:
// keepalives come every 25 seconds and would push everything else out of
// the log, and every start and stop names each worker goroutine.
var droppedLines = []string{"keepalive packet", "Routine:"}

// routineLines mark verbose lines that come with every handshake (about
// every two minutes) or every configuration; they are debug lines.
var routineLines = []string{
	"UAPI:", "handshake initiation", "handshake response", "retrying (try",
	" - Starting", " - Stopping", "Interface up requested", "Interface down requested", "UDP bind has been updated",
}

// verboseLine maps a verbose line of wireguard-go to the level and text of
// a tunnel log line, or reports false for a dropped line. Lines that are
// neither dropped nor routine are info lines.
func verboseLine(text string) (domain.LogLevel, string, bool) {
	switch {
	case containsAny(text, droppedLines):
		return "", "", false
	case containsAny(text, routineLines):
		return domain.LogLevelDebug, hideKeys(text), true
	}
	return domain.LogLevelInfo, hideKeys(text), true
}

// errorLine maps an error line of wireguard-go to a tunnel log line.
func errorLine(text string) (domain.LogLevel, string) {
	return domain.LogLevelError, hideKeys(text)
}

func hideKeys(text string) string { return hexKey.ReplaceAllString(text, "(hidden)") }

func containsAny(text string, parts []string) bool {
	for _, part := range parts {
		if strings.Contains(text, part) {
			return true
		}
	}
	return false
}
