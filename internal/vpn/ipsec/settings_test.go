package ipsec

import (
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"software.sslmate.com/src/go-pkcs12"

	"tunneldeck/internal/domain"
)

var testLAN = []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}

func TestValidate(t *testing.T) {
	pki := newTestPKI(t)
	modern := pki.pkcs12(t, pkcs12.Modern2023, "secret")
	legacy := pki.pkcs12(t, pkcs12.LegacyRC2, "secret")
	other := newTestPKI(t)
	tests := []struct {
		name     string
		settings map[string]any
		secrets  map[string]string
		want     map[string]string
	}{
		{name: "psk with defaults", settings: map[string]any{KeyGateway: "vpn.example.com"}, secrets: map[string]string{SecretPSK: testPSK}},
		{name: "literal gateway", settings: map[string]any{KeyGateway: "198.51.100.7"}, secrets: map[string]string{SecretPSK: testPSK}},
		{
			name:     "gateway missing and psk missing",
			settings: map[string]any{},
			want:     map[string]string{KeyGateway: "required", SecretPSK: "required"},
		},
		{
			name:     "gateway invalid",
			settings: map[string]any{KeyGateway: "vpn_example.com"}, secrets: map[string]string{SecretPSK: testPSK},
			want: map[string]string{KeyGateway: "host_invalid"},
		},
		{
			name:     "IPv6 gateway",
			settings: map[string]any{KeyGateway: "2001:db8::1"}, secrets: map[string]string{SecretPSK: testPSK},
			want: map[string]string{KeyGateway: "host_invalid"},
		},
		{
			name: "unknown choices and keys",
			settings: map[string]any{
				KeyGateway: "vpn.example.com", KeyTemplate: "sophos", KeyMode: "transport", KeyAuthMethod: "xauth", "dpd": "30s",
			},
			secrets: map[string]string{"pin": "1234"},
			want: map[string]string{
				KeyTemplate: "one_of", KeyMode: "one_of", KeyAuthMethod: "one_of", "dpd": "ipsec_unknown_setting",
				"pin": "ipsec_unknown_secret", SecretPSK: "required",
			},
		},
		{
			name: "net-to-net",
			settings: map[string]any{
				KeyGateway: "vpn.example.com", KeyMode: "netToNet",
				KeyLocalSubnets: []string{"192.168.1.0/24"}, KeyRemoteSubnets: []string{"10.20.0.0/16"},
			},
			secrets: map[string]string{SecretPSK: testPSK},
		},
		{
			name:     "net-to-net without local subnets",
			settings: map[string]any{KeyGateway: "vpn.example.com", KeyMode: "netToNet", KeyRemoteSubnets: []string{"10.20.0.0/16"}},
			secrets:  map[string]string{SecretPSK: testPSK},
			want:     map[string]string{KeyLocalSubnets: "required"},
		},
		{
			name: "local subnet outside the LAN",
			settings: map[string]any{
				KeyGateway: "vpn.example.com", KeyMode: "netToNet", KeyLocalSubnets: []string{"192.168.1.0/25", "192.168.2.0/24"}, KeyRemoteSubnets: []string{"10.20.0.0/16"},
			},
			secrets: map[string]string{SecretPSK: testPSK},
			want:    map[string]string{KeyLocalSubnets: "ipsec_local_subnet_outside_lan"},
		},
		{
			name: "local subnet everything",
			settings: map[string]any{
				KeyGateway: "vpn.example.com", KeyMode: "netToNet", KeyLocalSubnets: []string{"0.0.0.0/0"}, KeyRemoteSubnets: []string{"10.20.0.0/16"},
			},
			secrets: map[string]string{SecretPSK: testPSK},
			want:    map[string]string{KeyLocalSubnets: "ipsec_local_subnet_outside_lan"},
		},
		{
			name: "remote subnet problems",
			settings: map[string]any{
				KeyGateway: "198.51.100.7", KeyRemoteSubnets: []string{"198.51.100.0/24", "10.0.0.1/8", "10.1.0.0/16", "10.1.0.0/16"},
			},
			secrets: map[string]string{SecretPSK: testPSK},
			want:    map[string]string{KeyRemoteSubnets: "remote_network_contains_server"},
		},
		{
			name:     "remote subnet overlaps the LAN",
			settings: map[string]any{KeyGateway: "vpn.example.com", KeyRemoteSubnets: []string{"192.168.0.0/16"}},
			secrets:  map[string]string{SecretPSK: testPSK},
			want:     map[string]string{KeyRemoteSubnets: "remote_network_overlaps_lan"},
		},
		{
			name:     "remote subnets empty in virtual IP mode",
			settings: map[string]any{KeyGateway: "vpn.example.com", KeyRemoteSubnets: []string{}},
			secrets:  map[string]string{SecretPSK: testPSK},
		},
		{
			name:     "remote subnets missing in net-to-net mode",
			settings: map[string]any{KeyGateway: "vpn.example.com", KeyMode: "netToNet", KeyLocalSubnets: []string{"192.168.1.0/24"}},
			secrets:  map[string]string{SecretPSK: testPSK},
			want:     map[string]string{KeyRemoteSubnets: "required"},
		},
		{
			name: "identities",
			settings: map[string]any{
				KeyGateway: "vpn.example.com", KeyLocalID: "%any", KeyRemoteID: " vpn.example.com",
			},
			secrets: map[string]string{SecretPSK: testPSK},
			want:    map[string]string{KeyLocalID: "ipsec_identity_invalid", KeyRemoteID: "ipsec_identity_invalid"},
		},
		{
			name: "eap",
			settings: map[string]any{
				KeyGateway: "vpn.example.com", KeyAuthMethod: "eapMschapv2", KeyUsername: "alice",
				KeyCACert: pki.caPEM, KeyRemoteID: "vpn.example.com",
			},
			secrets: map[string]string{SecretEAPPassword: "pw"},
		},
		{
			name:     "eap without anything",
			settings: map[string]any{KeyGateway: "vpn.example.com", KeyAuthMethod: "eapMschapv2"},
			want: map[string]string{
				KeyUsername: "required", SecretEAPPassword: "required", KeyCACert: "required", KeyRemoteID: "required",
			},
		},
		{
			name: "certificate with PEM",
			settings: map[string]any{
				KeyGateway: "vpn.example.com", KeyAuthMethod: "certificate", KeyCACert: pki.caPEM,
				KeyClientCert: pki.clientPEM + pki.caPEM, KeyRemoteID: "vpn.example.com",
			},
			secrets: map[string]string{SecretClientKey: pki.keyPEM},
		},
		{
			name: "certificate with modern PKCS#12",
			settings: map[string]any{
				KeyGateway: "vpn.example.com", KeyAuthMethod: "certificate", KeyCACert: pki.caPEM, KeyRemoteID: "vpn.example.com",
			},
			secrets: map[string]string{SecretPKCS12: modern, SecretPKCS12Password: "secret"},
		},
		{
			name: "certificate with legacy PKCS#12 and a wrong password",
			settings: map[string]any{
				KeyGateway: "vpn.example.com", KeyAuthMethod: "certificate", KeyCACert: pki.caPEM, KeyRemoteID: "vpn.example.com",
			},
			secrets: map[string]string{SecretPKCS12: legacy, SecretPKCS12Password: "wrong"},
			want:    map[string]string{SecretPKCS12Password: "ipsec_pkcs12_password"},
		},
		{
			name: "certificate with PKCS#12 and PEM",
			settings: map[string]any{
				KeyGateway: "vpn.example.com", KeyAuthMethod: "certificate", KeyCACert: pki.caPEM,
				KeyClientCert: pki.clientPEM, KeyRemoteID: "vpn.example.com",
			},
			secrets: map[string]string{SecretPKCS12: modern, SecretPKCS12Password: "secret"},
			want:    map[string]string{SecretPKCS12: "ipsec_pkcs12_with_client_cert"},
		},
		{
			name: "certificate without client credentials",
			settings: map[string]any{
				KeyGateway: "vpn.example.com", KeyAuthMethod: "certificate", KeyCACert: "not a certificate", KeyRemoteID: "vpn.example.com",
			},
			want: map[string]string{
				KeyCACert: "ipsec_certificate_invalid", KeyClientCert: "ipsec_client_credentials_required",
				SecretClientKey: "ipsec_client_credentials_required",
			},
		},
		{
			name: "key of another certificate",
			settings: map[string]any{
				KeyGateway: "vpn.example.com", KeyAuthMethod: "certificate", KeyCACert: pki.caPEM,
				KeyClientCert: pki.clientPEM, KeyRemoteID: "vpn.example.com",
			},
			secrets: map[string]string{SecretClientKey: other.keyPEM},
			want:    map[string]string{SecretClientKey: "ipsec_key_mismatch"},
		},
		{
			name: "proposals",
			settings: map[string]any{
				KeyGateway:      "vpn.example.com",
				KeyIKEProposals: []string{"aes256-sha256-modp2048", "aes256gcm16-ecp256"},
				KeyESPProposals: []string{"aes256-sha256", "null-sha256"},
			},
			secrets: map[string]string{SecretPSK: testPSK},
			want:    map[string]string{KeyIKEProposals: "ipsec_proposal_incomplete", KeyESPProposals: "ipsec_proposal_forbidden"},
		},
		{
			name:     "psk too long",
			settings: map[string]any{KeyGateway: "vpn.example.com"},
			secrets:  map[string]string{SecretPSK: strings.Repeat("x", maxSecretLength+1)},
			want:     map[string]string{SecretPSK: "too_long"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := issueCodes(t, ValidateWithLAN(profileWith(tt.settings, tt.secrets), testLAN))
			want := tt.want
			if want == nil {
				want = map[string]string{}
			}
			if !maps.Equal(got, want) {
				t.Errorf("codes = %v, want %v", got, want)
			}
		})
	}
}

func TestValidateRejectsOtherProtocols(t *testing.T) {
	p := pskProfile()
	p.Protocol = domain.ProtocolWireGuard
	if codes := issueCodes(t, Validate(p)); codes["protocol"] != "protocol_unsupported" {
		t.Errorf("codes = %v", codes)
	}
}

func TestValidationMessagesNeverEchoSecrets(t *testing.T) {
	pki := newTestPKI(t)
	p := profileWith(map[string]any{
		KeyGateway: "vpn.example.com", KeyAuthMethod: "certificate", KeyCACert: pki.caPEM,
		KeyClientCert: pki.clientPEM, KeyRemoteID: "vpn.example.com",
	}, map[string]string{SecretClientKey: "-----BEGIN PRIVATE KEY-----\nc2VjcmV0LWtleS1tYXRlcmlhbA==\n-----END PRIVATE KEY-----\n"})
	err := Validate(p)
	if err == nil || strings.Contains(err.Error(), "c2VjcmV0") {
		t.Errorf("err = %v", err)
	}
}

func TestRemoteAndLocalNetworks(t *testing.T) {
	tests := []struct {
		name       string
		settings   map[string]any
		wantRemote []string
		wantLocal  []string
	}{
		{name: "default", settings: map[string]any{}},
		{
			name:       "virtual IP",
			settings:   map[string]any{KeyRemoteSubnets: []string{"0.0.0.0/0", "10.20.0.0/16", "bad", "10.20.0.0/16"}, KeyLocalSubnets: []string{"192.168.1.0/24"}},
			wantRemote: []string{"10.20.0.0/16"},
		},
		{
			name: "net-to-net",
			settings: map[string]any{
				KeyMode: "netToNet", KeyRemoteSubnets: []string{"10.20.0.0/16"}, KeyLocalSubnets: []string{"192.168.1.0/24", "192.168.1.0/24"},
			},
			wantRemote: []string{"10.20.0.0/16"}, wantLocal: []string{"192.168.1.0/24"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := profileWith(tt.settings, nil)
			if got := prefixStrings(RemoteNetworks(p)); !slices.Equal(got, tt.wantRemote) {
				t.Errorf("RemoteNetworks = %v, want %v", got, tt.wantRemote)
			}
			if got := prefixStrings(LocalNetworks(p)); !slices.Equal(got, tt.wantLocal) {
				t.Errorf("LocalNetworks = %v, want %v", got, tt.wantLocal)
			}
		})
	}
}

func prefixStrings(prefixes []netip.Prefix) []string {
	var out []string
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	return out
}

func TestSubnetIssueParams(t *testing.T) {
	p := profileWith(map[string]any{
		KeyGateway: "vpn.example.com", KeyRemoteSubnets: []string{"10.0.0.0/8", "192.168.1.0/24"},
	}, map[string]string{SecretPSK: testPSK})
	err := ValidateWithLAN(p, testLAN)
	v, ok := err.(*domain.ValidationError)
	if !ok {
		t.Fatalf("err = %v", err)
	}
	issue := v.Issues[KeyRemoteSubnets]
	if issue.Code != "remote_network_overlaps_lan" || issue.Params["entry"] != "2" || issue.Params["subnets"] != "192.168.1.0/24" {
		t.Errorf("issue = %+v", issue)
	}
}

// TestGatewayIdentityMustBeExact: with certificate or EAP authentication
// charon accepts any certificate matching the gateway identity, so forms
// it reads as ID_ANY, wildcards, subnets and ranges are refused there.
func TestGatewayIdentityMustBeExact(t *testing.T) {
	pki := newTestPKI(t)
	tests := []struct {
		id       string
		wantCode string
	}{
		{id: "vpn.example.com"},
		{id: "vpn-gw.example.com"},
		{id: "198.51.100.7"},
		{id: "2001:db8::1"},
		{id: "CN=vpn.example.com, O=Example"},
		{id: "admin@example.com"},
		{id: "fqdn:vpn.example.com"},
		{id: "*", wantCode: "ipsec_identity_wildcard"},
		{id: "0.0.0.0", wantCode: "ipsec_identity_wildcard"},
		{id: "::", wantCode: "ipsec_identity_wildcard"},
		{id: "0::0", wantCode: "ipsec_identity_wildcard"},
		{id: "%any", wantCode: "ipsec_identity_invalid"},
		{id: "%any6", wantCode: "ipsec_identity_invalid"},
		{id: "CN=*", wantCode: "ipsec_identity_wildcard"},
		{id: "C=DE, O=Example, CN=*", wantCode: "ipsec_identity_wildcard"},
		{id: "*.example.com", wantCode: "ipsec_identity_wildcard"},
		{id: "@*.example.com", wantCode: "ipsec_identity_wildcard"},
		{id: "*@example.com", wantCode: "ipsec_identity_wildcard"},
		{id: "198.51.100.0/24", wantCode: "ipsec_identity_wildcard"},
		{id: "0.0.0.0/0", wantCode: "ipsec_identity_wildcard"},
		{id: "198.51.100.1-198.51.100.9", wantCode: "ipsec_identity_wildcard"},
		{id: "ipv4net:198.51.100.0/24", wantCode: "ipsec_identity_wildcard"},
		{id: "IPv4Range:198.51.100.1-198.51.100.9", wantCode: "ipsec_identity_wildcard"},
		{id: "2001:db8::/32", wantCode: "ipsec_identity_wildcard"},
		{id: "{0}:vpn.example.com", wantCode: "ipsec_identity_wildcard"},
		{id: "{2}:vpn.example.com", wantCode: "ipsec_identity_wildcard"},
		{id: "fqdn:*.example.com", wantCode: "ipsec_identity_wildcard"},
	}
	for _, method := range []string{"certificate", "eapMschapv2"} {
		for _, tt := range tests {
			t.Run(method+" "+tt.id, func(t *testing.T) {
				p := profileWith(map[string]any{
					KeyGateway: "vpn.example.com", KeyAuthMethod: method, KeyCACert: pki.caPEM, KeyRemoteID: tt.id,
					KeyClientCert: pki.clientPEM, KeyUsername: "alice",
				}, map[string]string{SecretClientKey: pki.keyPEM, SecretEAPPassword: "pw"})
				if got := issueCodes(t, Validate(p))[KeyRemoteID]; got != tt.wantCode {
					t.Errorf("code = %q, want %q", got, tt.wantCode)
				}
			})
		}
	}
}

// TestPSKGatewayIdentityMayBeOpen: with a pre-shared key the key itself
// authenticates the gateway, so only %-forms are refused.
func TestPSKGatewayIdentityMayBeOpen(t *testing.T) {
	for id, want := range map[string]string{"*.example.com": "", "0.0.0.0": "", "%any": "ipsec_identity_invalid"} {
		p := profileWith(map[string]any{KeyGateway: "vpn.example.com", KeyRemoteID: id}, map[string]string{SecretPSK: testPSK})
		if got := issueCodes(t, Validate(p))[KeyRemoteID]; got != want {
			t.Errorf("%q: code = %q, want %q", id, got, want)
		}
	}
}
