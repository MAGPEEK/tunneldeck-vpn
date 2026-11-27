package domain

import (
	"net/netip"
	"net/url"
	"strconv"
)

// DefaultPublicIPLookupURL answers a plain-text GET with the caller's
// public IPv4 address.
const DefaultPublicIPLookupURL = "https://api.ipify.org"

// maxPublicIPLookupURLLength bounds the service URL.
const maxPublicIPLookupURLLength = 2048

// PublicIPLookup is the setting of the public IP detection: after every
// connect the address the internet sees through the tunnel is asked from
// the service at URL, which must answer with the address as plain text.
type PublicIPLookup struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
}

// DefaultPublicIPLookup is on and asks DefaultPublicIPLookupURL.
func DefaultPublicIPLookup() PublicIPLookup {
	return PublicIPLookup{Enabled: true, URL: DefaultPublicIPLookupURL}
}

// Validate requires an absolute http or https URL with a host and without
// user information, which would be a credential stored and shown in clear.
func (p PublicIPLookup) Validate() error {
	v := &ValidationError{}
	switch {
	case p.URL == "":
		v.AddIssue("url", Issue("required"), "is required")
	case len(p.URL) > maxPublicIPLookupURLLength:
		limit := strconv.Itoa(maxPublicIPLookupURLLength)
		v.AddIssue("url", Issue("too_long", "max", limit), "must be at most "+limit+" characters")
	default:
		checkLookupURL(v, p.URL)
	}
	return v.OrNil()
}

func checkLookupURL(v *ValidationError, raw string) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Hostname() == "" {
		v.AddIssue("url", Issue("public_ip_url_invalid"), "must be an absolute http or https URL")
		return
	}
	if u.User != nil {
		v.AddIssue("url", Issue("url_credentials_not_allowed"), "must not contain a user name or password")
	}
	if isInternalIPLiteral(u.Hostname()) {
		v.AddIssue("url", Issue("public_ip_url_internal"), "must not be an address on this host or inside this network")
	}
}

// cgnatPrefix is the carrier-grade NAT range (RFC 6598); the standard
// library has no predicate for it.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// isInternalIPLiteral reports whether host is an IP address literal in a
// range that must never be the public-IP lookup target (SSRF, SPEC §6.1):
// loopback (127.0.0.0/8, ::1), link-local (169.254.0.0/16 incl. the
// 169.254.169.254 metadata address, fe80::/10), private (10/8, 172.16/12,
// 192.168/16, fc00::/7) or carrier-grade NAT (100.64.0.0/10). A host name
// (not an IP literal) is allowed; it is resolved by the host resolver at
// request time, so this guard does not see it.
func isInternalIPLiteral(host string) bool {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsPrivate() ||
		cgnatPrefix.Contains(addr)
}
