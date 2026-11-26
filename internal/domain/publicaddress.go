package domain

import (
	"net/netip"
	"regexp"
	"strings"
)

// maxHostNameLength is the longest DNS name (RFC 1035 §2.3.4).
const maxHostNameLength = 253

// hostNameLabel is one label of a host name (RFC 1123 §2.1).
var hostNameLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// isPublicAddress reports whether s is an IPv4 address or a host name.
// Something that looks like an address but is not a valid IPv4 one, such
// as "300.1.2.3" or an IPv6 address, is rejected.
func isPublicAddress(s string) bool {
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Is4()
	}
	name := strings.TrimSuffix(s, ".")
	if name == "" || len(name) > maxHostNameLength {
		return false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if !hostNameLabel.MatchString(label) {
			return false
		}
	}
	return !isAllDigits(labels[len(labels)-1])
}

// isAllDigits reports whether s holds only ASCII digits; a numeric last
// label makes a name an attempted IPv4 address (RFC 3696 §2).
func isAllDigits(s string) bool {
	return strings.Trim(s, "0123456789") == ""
}
