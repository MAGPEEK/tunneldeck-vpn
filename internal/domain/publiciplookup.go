package domain

import (
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
}
