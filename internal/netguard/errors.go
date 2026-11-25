package netguard

import (
	"errors"
	"strings"
)

// NoBackendError reports that no iptables binary works on this host. It
// unwraps to the error of every attempted binary.
type NoBackendError struct {
	Attempts []error
}

// Error summarises why every candidate failed.
func (e *NoBackendError) Error() string {
	return "no usable iptables backend: " + errors.Join(e.Attempts...).Error()
}

// Unwrap returns the errors of the attempted binaries.
func (e *NoBackendError) Unwrap() []error {
	return e.Attempts
}

// absentMarkers are stderr fragments (C locale) meaning the chain, rule or
// route that a command refers to does not exist.
var absentMarkers = []string{
	"no chain/target/match by that name", // iptables -S/-F/-X on a missing chain
	"bad rule",                           // iptables -C/-D without a matching rule
	"couldn't load target",               // iptables jump to a missing chain
	"does not exist",                     // iptables-nft missing chain
	"no such file or directory",          // ip rule del without a matching rule
	"no such process",                    // ip route del without a matching route
	"cannot find device",                 // ip route del after the device vanished
}

// privilegeMarkers win over absentMarkers: a missing permission or kernel
// table must never be mistaken for "already absent".
var privilegeMarkers = []string{
	"permission denied",
	"operation not permitted",
	"can't initialize",
}

// isAbsent reports whether err is a command failure caused by the target
// object not existing.
func isAbsent(err error) bool {
	return stderrContains(err, absentMarkers) && !stderrContains(err, privilegeMarkers)
}

// isAlreadyExists reports whether err is an iptables -N on an existing chain.
func isAlreadyExists(err error) bool {
	return stderrContains(err, []string{"already exists"})
}

func stderrContains(err error, markers []string) bool {
	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) {
		return false
	}
	stderr := strings.ToLower(cmdErr.Stderr)
	for _, marker := range markers {
		if strings.Contains(stderr, marker) {
			return true
		}
	}
	return false
}
