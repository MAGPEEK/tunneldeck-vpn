package openvpn

import (
	"regexp"
	"strings"

	"tunneldeck/internal/domain"
)

// managementEchoPrefix starts the lines in which OpenVPN echoes management
// commands and states. They are dropped: they repeat what the driver
// already knows, and they show the username in clear text.
const managementEchoPrefix = "MANAGEMENT: "

// pushOptionsMarker ends the "Options error" lines OpenVPN logs for a
// pushed option it does not accept. The pull filters keep the usual ones
// away (render.go); any other is expected, not a failure.
const pushOptionsMarker = "([PUSH-OPTIONS])"

// expectedWarnings are warnings every start of a working profile logs; they
// are info. The credentials stay cached on purpose: a TLS renegotiation
// needs them.
var expectedWarnings = []string{"this configuration may cache passwords in memory"}

// cipherNoneWarnings mark the warnings openvpn logs because the profile's
// cipher is "none" (data-ciphers none:CHACHA20-POLY1305), whatever the
// server negotiates.
var cipherNoneWarnings = []string{"cipher 'none'", "'--cipher none'"}

// cipherNoneNote follows the first of those warnings of a process.
const cipherNoneNote = "TunnelDeck-VPN: the warnings about cipher 'none' come from the profile setting Cipher = none, " +
	"which allows an unencrypted data channel when the server offers one; the line \"Data Channel: cipher …\" names the cipher in use"

// outputTimestamp is the prefix OpenVPN puts on lines written to stdout.
var outputTimestamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} `)

// outputErrorPrefixes start the stdout lines of fatal start-up problems,
// which happen before the management interface exists.
var outputErrorPrefixes = []string{"Options error", "ERROR:", "FATAL:", "Exiting due to fatal error"}

func isManagementEcho(text string) bool {
	return strings.HasPrefix(text, managementEchoPrefix)
}

// isCipherNoneWarning reports whether text warns about cipher "none".
func isCipherNoneWarning(text string) bool {
	return containsAny(text, cipherNoneWarnings)
}

// managementLogLevel maps the flags of a >LOG: line (F fatal, N non-fatal
// error, W warning, I info, D debug) to a level. The expected warnings of
// every start are info; the [PUSH-OPTIONS] lines are flagged N but are
// only warnings.
func managementLogLevel(flags, text string) domain.LogLevel {
	switch {
	case containsAny(text, expectedWarnings):
		return domain.LogLevelInfo
	case strings.Contains(text, pushOptionsMarker):
		return domain.LogLevelWarn
	case strings.ContainsAny(flags, "FN"):
		return domain.LogLevelError
	case strings.Contains(flags, "W"):
		return domain.LogLevelWarn
	case strings.Contains(flags, "D"):
		return domain.LogLevelDebug
	}
	return domain.LogLevelInfo
}

// stripOutputTimestamp removes the date and time OpenVPN writes in front of
// every stdout line.
func stripOutputTimestamp(line string) string {
	return outputTimestamp.ReplaceAllString(line, "")
}

// outputLogLevel classifies a stdout line, which carries no flags.
func outputLogLevel(text string) domain.LogLevel {
	switch {
	case containsAny(text, expectedWarnings):
		return domain.LogLevelInfo
	case strings.Contains(text, pushOptionsMarker):
		return domain.LogLevelWarn
	case hasAnyPrefix(text, outputErrorPrefixes):
		return domain.LogLevelError
	case strings.Contains(text, "WARNING") || strings.HasPrefix(text, "DEPRECATED OPTION"):
		return domain.LogLevelWarn
	}
	return domain.LogLevelInfo
}

func containsAny(text string, fragments []string) bool {
	for _, fragment := range fragments {
		if strings.Contains(text, fragment) {
			return true
		}
	}
	return false
}
