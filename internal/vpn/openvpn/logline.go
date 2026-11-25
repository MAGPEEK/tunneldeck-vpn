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

// pushOptionsMarker ends the "Options error" lines that route-nopull causes
// for every pushed option it drops. They are expected, not failures.
const pushOptionsMarker = "([PUSH-OPTIONS])"

// outputTimestamp is the prefix OpenVPN puts on lines written to stdout.
var outputTimestamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} `)

// outputErrorPrefixes start the stdout lines of fatal start-up problems,
// which happen before the management interface exists.
var outputErrorPrefixes = []string{"Options error", "ERROR:", "FATAL:", "Exiting due to fatal error"}

func isManagementEcho(text string) bool {
	return strings.HasPrefix(text, managementEchoPrefix)
}

// managementLogLevel maps the flags of a >LOG: line (F fatal, N non-fatal
// error, W warning, I info, D debug) to a level. The expected warnings of
// every mdex start are flagged W; the [PUSH-OPTIONS] lines are flagged N
// but are only warnings.
func managementLogLevel(flags, text string) domain.LogLevel {
	switch {
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
	case strings.Contains(text, pushOptionsMarker):
		return domain.LogLevelWarn
	case hasAnyPrefix(text, outputErrorPrefixes):
		return domain.LogLevelError
	case strings.Contains(text, "WARNING") || strings.HasPrefix(text, "DEPRECATED OPTION"):
		return domain.LogLevelWarn
	}
	return domain.LogLevelInfo
}
