package ipsec

import (
	"regexp"
	"strings"

	"tunneldeck/internal/domain"
)

// charon logs "<thread>[<group>] <text>" (filelog without time stamps).
var (
	charonLine = regexp.MustCompile(`^\d+\[([A-Z]+)\] (.*)$`)
	// tunCreated is kernel-libipsec's line about its TUN device.
	tunCreated = regexp.MustCompile(`^created TUN device: (\S+)$`)
)

// quietGroups log every packet and message parse: debug.
var quietGroups = map[string]bool{"NET": true, "ENC": true, "ASN": true}

// logLine turns one line of charon's output into the tunnel log: the group
// stays, the thread number goes. Packet and parser lines are debug, lines
// about failures warnings, others info.
func logLine(raw string) (domain.LogLevel, string) {
	match := charonLine.FindStringSubmatch(raw)
	if match == nil {
		return domain.LogLevelInfo, raw
	}
	group, text := match[1], match[2]
	line := "[" + group + "] " + text
	lower := strings.ToLower(text)
	switch {
	case quietGroups[group]:
		return domain.LogLevelDebug, line
	case strings.Contains(lower, "failed") || strings.Contains(lower, "error") || strings.Contains(lower, "unable"):
		return domain.LogLevelWarn, line
	}
	return domain.LogLevelInfo, line
}

// tunDevice returns the TUN device a log line reports kernel-libipsec
// created.
func tunDevice(raw string) (string, bool) {
	match := charonLine.FindStringSubmatch(raw)
	if match == nil {
		return "", false
	}
	device := tunCreated.FindStringSubmatch(match[2])
	if device == nil {
		return "", false
	}
	return device[1], true
}

// logFailures are charon's lines about IKEv1 rejections, which raise no
// VICI alert: refused XAuth credentials of this side and the gateway's
// error notifies (IKEv2 reports these as alerts).
var logFailures = []struct {
	line    *regexp.Regexp
	failure failure
}{
	{regexp.MustCompile(`^XAuth authentication of '.*' \(myself\) failed$`), failure{domain.ErrorCodeAuthFailed,
		"the gateway rejected the XAuth username or password; check them and the group name (local identity)"}},
	{regexp.MustCompile(`^received AUTHENTICATION_FAILED error notify$`), failure{domain.ErrorCodeAuthFailed,
		"the gateway rejected the authentication (AUTHENTICATION_FAILED); check the pre-shared key and the group name (local identity)"}},
	{regexp.MustCompile(`^received NO_PROPOSAL_CHOSEN error notify$`), failure{domain.ErrorCodeProposalMismatch,
		"the gateway accepted none of the proposals (NO_PROPOSAL_CHOSEN); compare them with the gateway's"}},
}

// logFailure returns the failure a log line reports, if any.
func logFailure(raw string) (failure, bool) {
	match := charonLine.FindStringSubmatch(raw)
	if match == nil {
		return failure{}, false
	}
	for _, f := range logFailures {
		if f.line.MatchString(match[2]) {
			return f.failure, true
		}
	}
	return failure{}, false
}
