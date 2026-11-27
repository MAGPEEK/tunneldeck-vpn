package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestPublicIPLookupValidate(t *testing.T) {
	tests := []struct {
		name     string
		settings PublicIPLookup
		wantCode string // "" = valid
	}{
		{name: "default", settings: DefaultPublicIPLookup()},
		{name: "disabled with url", settings: PublicIPLookup{URL: "https://ifconfig.me/ip"}},
		{name: "http with port and path", settings: PublicIPLookup{Enabled: true, URL: "http://192.0.2.1:8080/ip?format=text"}},
		{name: "empty", settings: PublicIPLookup{Enabled: true}, wantCode: "required"},
		{name: "too long", settings: PublicIPLookup{URL: "https://example.com/" + strings.Repeat("a", 2048)}, wantCode: "too_long"},
		{name: "relative", settings: PublicIPLookup{URL: "/ip"}, wantCode: "public_ip_url_invalid"},
		{name: "no scheme", settings: PublicIPLookup{URL: "api.ipify.org"}, wantCode: "public_ip_url_invalid"},
		{name: "ftp", settings: PublicIPLookup{URL: "ftp://example.com/ip"}, wantCode: "public_ip_url_invalid"},
		{name: "no host", settings: PublicIPLookup{URL: "https:///ip"}, wantCode: "public_ip_url_invalid"},
		{name: "port only", settings: PublicIPLookup{URL: "https://:443/ip"}, wantCode: "public_ip_url_invalid"},
		{name: "unparsable", settings: PublicIPLookup{URL: "https://exa mple.com\x7f"}, wantCode: "public_ip_url_invalid"},
		{name: "credentials", settings: PublicIPLookup{URL: "https://user:s3cr3t@example.com/ip"}, wantCode: "url_credentials_not_allowed"},
		// H2: IP-literal hosts in internal ranges are rejected (SPEC §6.1).
		{name: "public host name", settings: PublicIPLookup{URL: "https://api.ipify.org"}},
		{name: "public IPv4 literal", settings: PublicIPLookup{URL: "https://203.0.113.10/ip"}},
		{name: "loopback v4", settings: PublicIPLookup{URL: "http://127.0.0.1/ip"}, wantCode: "public_ip_url_internal"},
		{name: "loopback v4 high", settings: PublicIPLookup{URL: "http://127.9.9.9:8080/ip"}, wantCode: "public_ip_url_internal"},
		{name: "loopback v6", settings: PublicIPLookup{URL: "http://[::1]/ip"}, wantCode: "public_ip_url_internal"},
		{name: "link-local v4", settings: PublicIPLookup{URL: "http://169.254.1.1/ip"}, wantCode: "public_ip_url_internal"},
		{name: "metadata address", settings: PublicIPLookup{URL: "http://169.254.169.254/latest/meta-data"}, wantCode: "public_ip_url_internal"},
		{name: "link-local v6", settings: PublicIPLookup{URL: "http://[fe80::1]/ip"}, wantCode: "public_ip_url_internal"},
		{name: "private 10", settings: PublicIPLookup{URL: "http://10.0.0.1/ip"}, wantCode: "public_ip_url_internal"},
		{name: "private 172.16", settings: PublicIPLookup{URL: "http://172.16.5.4/ip"}, wantCode: "public_ip_url_internal"},
		{name: "private 192.168", settings: PublicIPLookup{URL: "http://192.168.1.1/ip"}, wantCode: "public_ip_url_internal"},
		{name: "private v6 ula", settings: PublicIPLookup{URL: "http://[fc00::1]/ip"}, wantCode: "public_ip_url_internal"},
		{name: "cgnat", settings: PublicIPLookup{URL: "http://100.64.0.1/ip"}, wantCode: "public_ip_url_internal"},
		{name: "ipv4-mapped loopback", settings: PublicIPLookup{URL: "http://[::ffff:127.0.0.1]/ip"}, wantCode: "public_ip_url_internal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.settings.Validate()
			if tt.wantCode == "" {
				if err != nil {
					t.Fatalf("Validate = %v", err)
				}
				return
			}
			var v *ValidationError
			if !errors.As(err, &v) || v.Issues["url"].Code != tt.wantCode {
				t.Fatalf("Validate = %v, want url issue %s", err, tt.wantCode)
			}
			if strings.Contains(v.Fields["url"], "s3cr3t") {
				t.Errorf("message %q echoes the URL", v.Fields["url"])
			}
		})
	}
}

func TestDefaultPublicIPLookup(t *testing.T) {
	d := DefaultPublicIPLookup()
	if !d.Enabled || d.URL != "https://api.ipify.org" || d.Validate() != nil {
		t.Fatalf("DefaultPublicIPLookup = %+v", d)
	}
}
