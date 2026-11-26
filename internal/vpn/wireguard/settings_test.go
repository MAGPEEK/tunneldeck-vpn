package wireguard

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"tunneldeck/internal/domain"
)

// Test keys: the RFC 7748 §6.1 pair of Alice is the profile's own key,
// Bob's public key the server's.
const bobPublicHex = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"

func testPrivateKey(t *testing.T) string { return keyFromHex(t, rfcPrivateHex).Base64() }
func testPeerKey(t *testing.T) string    { return keyFromHex(t, bobPublicHex).Base64() }
func testPresharedKey() string           { return Key{1, 2, 3}.Base64() }

// validProfile returns a WireGuard profile that passes Validate; change
// applies changes to its settings and secrets.
func validProfile(t *testing.T, change func(s domain.Settings, secrets map[string]string)) domain.Profile {
	t.Helper()
	s := domain.Settings{}
	s.SetString(KeyAddress, "10.66.0.2/32")
	s.SetInt(KeyMTU, 1420)
	s.SetString(KeyPeerPublicKey, testPeerKey(t))
	s.SetString(KeyEndpoint, "vpn.example.com:51820")
	s.SetStringList(KeyAllowedIPs, []string{"0.0.0.0/0", "10.20.0.0/16"})
	s.SetInt(KeyPersistentKeepalive, 25)
	secrets := map[string]string{SecretPrivateKey: testPrivateKey(t), SecretPresharedKey: testPresharedKey()}
	if change != nil {
		change(s, secrets)
	}
	return domain.Profile{Name: "WG", Protocol: domain.ProtocolWireGuard, Settings: s, Secrets: secrets}
}

func TestValidate(t *testing.T) {
	lan := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	tests := []struct {
		name   string
		change func(s domain.Settings, secrets map[string]string)
		field  string // "" = valid
		code   string
	}{
		{"valid", nil, "", ""},
		{"minimal", func(s domain.Settings, secrets map[string]string) {
			delete(s, KeyMTU)
			delete(s, KeyPersistentKeepalive)
			delete(secrets, SecretPresharedKey)
			s.SetString(KeyEndpoint, "203.0.113.7")
		}, "", ""},
		{"plain address", func(s domain.Settings, _ map[string]string) { s.SetString(KeyAddress, "10.66.0.2") }, "", ""},
		{"IPv6 endpoint", func(s domain.Settings, _ map[string]string) { s.SetString(KeyEndpoint, "[2001:db8::1]:51820") }, "", ""},
		{"keepalive off", func(s domain.Settings, _ map[string]string) { s.SetInt(KeyPersistentKeepalive, 0) }, "", ""},
		{"private key missing", func(_ domain.Settings, secrets map[string]string) { delete(secrets, SecretPrivateKey) },
			SecretPrivateKey, "required"},
		{"private key invalid", func(_ domain.Settings, secrets map[string]string) { secrets[SecretPrivateKey] = "abc" },
			SecretPrivateKey, "wireguard_key_invalid"},
		{"private key zero", func(_ domain.Settings, secrets map[string]string) { secrets[SecretPrivateKey] = Key{}.Base64() },
			SecretPrivateKey, "wireguard_key_invalid"},
		{"preshared key invalid", func(_ domain.Settings, secrets map[string]string) { secrets[SecretPresharedKey] = "x" },
			SecretPresharedKey, "wireguard_key_invalid"},
		{"unknown secret", func(_ domain.Settings, secrets map[string]string) { secrets["password"] = "x" },
			"password", "wireguard_unknown_secret"},
		{"unknown setting", func(s domain.Settings, _ map[string]string) { s.SetString("dns", "1.1.1.1") },
			"dns", "wireguard_unknown_setting"},
		{"address missing", func(s domain.Settings, _ map[string]string) { delete(s, KeyAddress) }, KeyAddress, "required"},
		{"address IPv6", func(s domain.Settings, _ map[string]string) { s.SetString(KeyAddress, "fd00::2/128") },
			KeyAddress, "wireguard_address_invalid"},
		{"address /0", func(s domain.Settings, _ map[string]string) { s.SetString(KeyAddress, "10.66.0.2/0") },
			KeyAddress, "wireguard_address_invalid"},
		{"address not a string", func(s domain.Settings, _ map[string]string) { s.SetInt(KeyAddress, 1) }, KeyAddress, "not_string"},
		{"address in the LAN", func(s domain.Settings, _ map[string]string) { s.SetString(KeyAddress, "192.168.1.201/32") },
			KeyAddress, "wireguard_address_overlaps_lan"},
		{"address network covers the LAN", func(s domain.Settings, _ map[string]string) { s.SetString(KeyAddress, "192.168.5.2/16") },
			KeyAddress, "wireguard_address_overlaps_lan"},
		{"MTU too small", func(s domain.Settings, _ map[string]string) { s.SetInt(KeyMTU, 1279) }, KeyMTU, "number_between"},
		{"MTU too large", func(s domain.Settings, _ map[string]string) { s.SetInt(KeyMTU, 1500) }, KeyMTU, "number_between"},
		{"MTU text", func(s domain.Settings, _ map[string]string) { s.SetString(KeyMTU, "1420") }, KeyMTU, "number_between"},
		{"peer key missing", func(s domain.Settings, _ map[string]string) { delete(s, KeyPeerPublicKey) }, KeyPeerPublicKey, "required"},
		{"peer key invalid", func(s domain.Settings, _ map[string]string) { s.SetString(KeyPeerPublicKey, "AAAA") },
			KeyPeerPublicKey, "wireguard_key_invalid"},
		{"peer key is own key", func(s domain.Settings, _ map[string]string) {
			s.SetString(KeyPeerPublicKey, keyFromHex(t, rfcPublicHex).Base64())
		}, KeyPeerPublicKey, "wireguard_peer_is_self"},
		{"endpoint missing", func(s domain.Settings, _ map[string]string) { delete(s, KeyEndpoint) }, KeyEndpoint, "required"},
		{"endpoint bad port", func(s domain.Settings, _ map[string]string) { s.SetString(KeyEndpoint, "vpn.example.com:0") },
			KeyEndpoint, "wireguard_endpoint_invalid"},
		{"endpoint bad host", func(s domain.Settings, _ map[string]string) { s.SetString(KeyEndpoint, "vpn_example.com:51820") },
			KeyEndpoint, "wireguard_endpoint_invalid"},
		{"keepalive negative", func(s domain.Settings, _ map[string]string) { s.SetInt(KeyPersistentKeepalive, -1) },
			KeyPersistentKeepalive, "number_between"},
		{"keepalive too large", func(s domain.Settings, _ map[string]string) { s.SetInt(KeyPersistentKeepalive, 65536) },
			KeyPersistentKeepalive, "number_between"},
		{"allowed IPs missing", func(s domain.Settings, _ map[string]string) { delete(s, KeyAllowedIPs) }, KeyAllowedIPs, "required"},
		{"allowed IPs empty", func(s domain.Settings, _ map[string]string) { s.SetStringList(KeyAllowedIPs, nil) },
			KeyAllowedIPs, "required"},
		{"allowed IPs not a list", func(s domain.Settings, _ map[string]string) { s.SetString(KeyAllowedIPs, "0.0.0.0/0") },
			KeyAllowedIPs, "not_string_list"},
		{"allowed IP IPv6", func(s domain.Settings, _ map[string]string) { s.SetStringList(KeyAllowedIPs, []string{"::/0"}) },
			KeyAllowedIPs, "remote_network_not_cidr"},
		{"allowed IP host bits", func(s domain.Settings, _ map[string]string) { s.SetStringList(KeyAllowedIPs, []string{"10.20.0.1/16"}) },
			KeyAllowedIPs, "remote_network_not_canonical"},
		{"allowed IP twice", func(s domain.Settings, _ map[string]string) {
			s.SetStringList(KeyAllowedIPs, []string{"10.20.0.0/16", "10.20.0.0/16"})
		}, KeyAllowedIPs, "remote_network_duplicate"},
		{"allowed IP overlaps LAN", func(s domain.Settings, _ map[string]string) {
			s.SetStringList(KeyAllowedIPs, []string{"0.0.0.0/0", "192.168.0.0/16"})
		}, KeyAllowedIPs, "remote_network_overlaps_lan"},
		{"allowed IP contains the endpoint", func(s domain.Settings, _ map[string]string) {
			s.SetString(KeyEndpoint, "203.0.113.7:51820")
			s.SetStringList(KeyAllowedIPs, []string{"203.0.113.0/24"})
		}, KeyAllowedIPs, "remote_network_contains_server"},
		{"too many allowed IPs", func(s domain.Settings, _ map[string]string) {
			entries := make([]string, maxAllowedIPs+1)
			for i := range entries {
				entries[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16).String()
			}
			s.SetStringList(KeyAllowedIPs, entries)
		}, KeyAllowedIPs, "too_many_entries"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWithLAN(validProfile(t, tt.change), lan)
			if tt.field == "" {
				if err != nil {
					t.Fatalf("Validate = %v, want nil", err)
				}
				return
			}
			var v *domain.ValidationError
			if !errors.As(err, &v) || !errors.Is(err, domain.ErrValidation) {
				t.Fatalf("Validate = %v, want a validation error", err)
			}
			if got := v.Issues[tt.field].Code; got != tt.code {
				t.Errorf("issue of %q = %q, want %q (fields %v)", tt.field, got, tt.code, v.Fields)
			}
		})
	}
}

func TestValidateRejectsOtherProtocols(t *testing.T) {
	p := validProfile(t, nil)
	p.Protocol = domain.ProtocolOpenVPN
	var v *domain.ValidationError
	if err := Validate(p); !errors.As(err, &v) || v.Issues["protocol"].Code != "protocol_unsupported" {
		t.Errorf("Validate = %v", err)
	}
}

func TestRemoteNetworks(t *testing.T) {
	tests := []struct {
		name    string
		allowed []string
		want    []string
	}{
		{"everything only", []string{"0.0.0.0/0"}, nil},
		{"networks besides everything", []string{"0.0.0.0/0", "10.20.0.0/16", "192.168.178.0/24"}, []string{"10.20.0.0/16", "192.168.178.0/24"}},
		{"invalid and duplicate entries skipped", []string{"10.20.0.0/16", "::/0", "10.20.0.0/16", "x"}, []string{"10.20.0.0/16"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validProfile(t, func(s domain.Settings, _ map[string]string) { s.SetStringList(KeyAllowedIPs, tt.allowed) })
			var got []string
			for _, prefix := range (&Driver{}).RemoteNetworks(p) {
				got = append(got, prefix.String())
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("RemoteNetworks = %v, want %v", got, tt.want)
			}
		})
	}
	if got := RemoteNetworks(domain.Profile{Settings: domain.Settings{}}); got != nil {
		t.Errorf("without allowed IPs = %v", got)
	}
}

func TestDriverValidateUsesTheLAN(t *testing.T) {
	p := validProfile(t, func(s domain.Settings, _ map[string]string) {
		s.SetStringList(KeyAllowedIPs, []string{"192.168.1.0/24"})
	})
	lan := func(context.Context) ([]netip.Prefix, error) {
		return []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, nil
	}
	if err := New(Options{LANSubnets: lan}).Validate(p); err == nil {
		t.Error("Validate accepted allowed IPs inside the LAN")
	}
	failing := func(context.Context) ([]netip.Prefix, error) { return nil, errors.New("no LAN") }
	if err := New(Options{LANSubnets: failing}).Validate(p); err != nil {
		t.Errorf("Validate without a detectable LAN = %v", err)
	}
}

func TestDeriveReturnsThePublicKeyOnly(t *testing.T) {
	d := New(Options{})
	got := d.Derive(validProfile(t, nil))
	if want := keyFromHex(t, rfcPublicHex).Base64(); len(got) != 1 || got[DerivedPublicKey] != want {
		t.Errorf("Derive = %v, want only %s", got, want)
	}
	if got := d.Derive(domain.Profile{Secrets: map[string]string{SecretPrivateKey: "bad"}}); got != nil {
		t.Errorf("Derive of an invalid key = %v", got)
	}
}
