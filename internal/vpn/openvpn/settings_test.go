package openvpn

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

func TestValidateAcceptsEveryAuthMode(t *testing.T) {
	m := testMaterial()
	tests := []struct {
		name     string
		settings map[string]any
		secrets  vpn.Secrets
	}{
		{name: "password", settings: mdexSettings(), secrets: mdexSecrets()},
		{
			name: "certificate",
			settings: map[string]any{
				KeyRemoteHost: "vpn.example.com", KeyAuthMode: AuthModeCertificate,
				KeyCACert: m.caPEM, KeyClientCert: m.clientCertPEM,
			},
			secrets: vpn.Secrets{SecretClientKey: m.clientKeyPEM, SecretTLSCryptKey: m.tlsCryptKey},
		},
		{
			name: "certificate+password",
			settings: map[string]any{
				KeyRemoteHost: "2001:db8::1", KeyAuthMode: AuthModeCertificateAndPassword,
				KeyUsername: "alice", KeyCACert: m.caPEM, KeyClientCert: m.clientCertPEM,
			},
			secrets: vpn.Secrets{
				SecretPassword: "pw", SecretClientKey: m.rsaKeyPEM,
				SecretKeyPassphrase: "phrase", SecretTLSAuthKey: m.tlsAuthKey,
			},
		},
		{
			name: "certificate as PKCS#12 with wrapped base64",
			settings: map[string]any{
				KeyRemoteHost: "vpn.example.com", KeyAuthMode: AuthModeCertificate, KeyCACert: m.caPEM,
			},
			secrets: vpn.Secrets{SecretPKCS12: mustCanonicalPKCS12(t, m.pkcs12), SecretKeyPassphrase: "phrase"},
		},
		{
			name: "remote networks",
			settings: map[string]any{
				KeyRemoteHost: "198.51.100.7", KeyUsername: "u", KeyCACert: m.caPEM,
				KeyRemoteNetworks: []string{"10.99.0.0/24", "10.98.0.0/16", "192.0.2.1/32", "198.51.100.0/31"},
			},
			secrets: vpn.Secrets{SecretPassword: "pw"},
		},
		{
			name:     "defaults only",
			settings: map[string]any{KeyRemoteHost: "vpn.example.com.", KeyUsername: "u", KeyCACert: m.caPEM},
			secrets:  vpn.Secrets{SecretPassword: "pw"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Validate(newProfile(t, tt.settings, tt.secrets)); err != nil {
				t.Errorf("Validate: %v", err)
			}
		})
	}
}

func TestValidateRejects(t *testing.T) {
	m := testMaterial()
	certificateMode := func(s map[string]any) {
		s[KeyAuthMode] = AuthModeCertificate
		s[KeyClientCert] = m.clientCertPEM
	}
	tests := []struct {
		name      string
		change    func(s map[string]any, secrets vpn.Secrets)
		wantField string
	}{
		{"missing remote host", func(s map[string]any, _ vpn.Secrets) { delete(s, KeyRemoteHost) }, KeyRemoteHost},
		{"remote host with space", func(s map[string]any, _ vpn.Secrets) { s[KeyRemoteHost] = "a b" }, KeyRemoteHost},
		{"remote host with option", func(s map[string]any, _ vpn.Secrets) { s[KeyRemoteHost] = "x\nup /bin/sh" }, KeyRemoteHost},
		{"remote host label dash", func(s map[string]any, _ vpn.Secrets) { s[KeyRemoteHost] = "-x.example" }, KeyRemoteHost},
		{"remote host too long", func(s map[string]any, _ vpn.Secrets) {
			s[KeyRemoteHost] = strings.Repeat("a.", 120) + "de"
		}, KeyRemoteHost},
		{"remote host not a string", func(s map[string]any, _ vpn.Secrets) { s[KeyRemoteHost] = 7 }, KeyRemoteHost},
		{"port zero", func(s map[string]any, _ vpn.Secrets) { s[KeyPort] = 0 }, KeyPort},
		{"port too big", func(s map[string]any, _ vpn.Secrets) { s[KeyPort] = 65536 }, KeyPort},
		{"port as string", func(s map[string]any, _ vpn.Secrets) { s[KeyPort] = "1194" }, KeyPort},
		{"proto icmp", func(s map[string]any, _ vpn.Secrets) { s[KeyProto] = "icmp" }, KeyProto},
		{"compression lz4", func(s map[string]any, _ vpn.Secrets) { s[KeyCompression] = "lz4" }, KeyCompression},
		{"auth mode unknown", func(s map[string]any, _ vpn.Secrets) { s[KeyAuthMode] = "token" }, KeyAuthMode},
		{"key direction 2", func(s map[string]any, _ vpn.Secrets) { s[KeyKeyDirection] = "2" }, KeyKeyDirection},
		{"missing username", func(s map[string]any, _ vpn.Secrets) { delete(s, KeyUsername) }, KeyUsername},
		{"username with newline", func(s map[string]any, _ vpn.Secrets) { s[KeyUsername] = "a\nb" }, KeyUsername},
		{"missing password", func(_ map[string]any, sec vpn.Secrets) { delete(sec, SecretPassword) }, SecretPassword},
		{"password with CR", func(_ map[string]any, sec vpn.Secrets) { sec[SecretPassword] = "a\rb" }, SecretPassword},
		{"password with NUL", func(_ map[string]any, sec vpn.Secrets) { sec[SecretPassword] = "a\x00b" }, SecretPassword},
		{"password too long", func(_ map[string]any, sec vpn.Secrets) {
			sec[SecretPassword] = strings.Repeat("p", 256)
		}, SecretPassword},
		{"missing CA", func(s map[string]any, _ vpn.Secrets) { delete(s, KeyCACert) }, KeyCACert},
		{"garbage CA", func(s map[string]any, _ vpn.Secrets) { s[KeyCACert] = "not a certificate" }, KeyCACert},
		{"key as CA", func(s map[string]any, _ vpn.Secrets) { s[KeyCACert] = m.clientKeyPEM }, KeyCACert},
		{"missing client cert", func(s map[string]any, sec vpn.Secrets) {
			certificateMode(s)
			delete(s, KeyClientCert)
			sec[SecretClientKey] = m.clientKeyPEM
		}, KeyClientCert},
		{"missing client key", func(s map[string]any, _ vpn.Secrets) { certificateMode(s) }, SecretClientKey},
		{"certificate as client key", func(s map[string]any, sec vpn.Secrets) {
			certificateMode(s)
			sec[SecretClientKey] = m.caPEM
		}, SecretClientKey},
		{"passphrase with LF", func(s map[string]any, sec vpn.Secrets) {
			certificateMode(s)
			sec[SecretClientKey] = m.clientKeyPEM
			sec[SecretKeyPassphrase] = "a\nb"
		}, SecretKeyPassphrase},
		{"tls-auth and tls-crypt", func(_ map[string]any, sec vpn.Secrets) {
			sec[SecretTLSAuthKey] = m.tlsAuthKey
			sec[SecretTLSCryptKey] = m.tlsCryptKey
		}, SecretTLSCryptKey},
		{"bad tls-auth key", func(_ map[string]any, sec vpn.Secrets) { sec[SecretTLSAuthKey] = "abc" }, SecretTLSAuthKey},
		{"cipher with space", func(s map[string]any, _ vpn.Secrets) { s[KeyCipher] = "AES 256" }, KeyCipher},
		{"cipher too long", func(s map[string]any, _ vpn.Secrets) { s[KeyCipher] = strings.Repeat("A", 201) }, KeyCipher},
		{"digest with quote", func(s map[string]any, _ vpn.Secrets) { s[KeyAuthDigest] = `SHA"1` }, KeyAuthDigest},
		{"resolve retry words", func(s map[string]any, _ vpn.Secrets) { s[KeyResolveRetry] = "forever" }, KeyResolveRetry},
		{"keepalive one number", func(s map[string]any, _ vpn.Secrets) { s[KeyKeepalive] = "10" }, KeyKeepalive},
		{"keepalive zero", func(s map[string]any, _ vpn.Secrets) { s[KeyKeepalive] = "0 60" }, KeyKeepalive},
		{"verify not bool", func(s map[string]any, _ vpn.Secrets) { s[KeyVerifyServerCertUsage] = "yes" }, KeyVerifyServerCertUsage},
		{"extra options not a list", func(s map[string]any, _ vpn.Secrets) { s[KeyExtraOptions] = "float" }, KeyExtraOptions},
		{"extra option runs code", func(s map[string]any, _ vpn.Secrets) {
			s[KeyExtraOptions] = []string{"float", "--up /bin/sh"}
		}, KeyExtraOptions},
		{"pkcs12 and client key", func(s map[string]any, sec vpn.Secrets) {
			certificateMode(s)
			delete(s, KeyClientCert)
			sec[SecretClientKey] = m.clientKeyPEM
			sec[SecretPKCS12] = m.pkcs12
		}, SecretPKCS12},
		{"pkcs12 and client cert", func(s map[string]any, sec vpn.Secrets) {
			certificateMode(s)
			sec[SecretPKCS12] = m.pkcs12
		}, SecretPKCS12},
		{"pkcs12 not base64", func(s map[string]any, sec vpn.Secrets) {
			certificateMode(s)
			delete(s, KeyClientCert)
			sec[SecretPKCS12] = "not base64!"
		}, SecretPKCS12},
		{"pkcs12 is a PEM key", func(s map[string]any, sec vpn.Secrets) {
			certificateMode(s)
			delete(s, KeyClientCert)
			sec[SecretPKCS12] = m.clientKeyPEM
		}, SecretPKCS12},
		{"pkcs12 too large", func(s map[string]any, sec vpn.Secrets) {
			certificateMode(s)
			delete(s, KeyClientCert)
			sec[SecretPKCS12] = base64.StdEncoding.EncodeToString(fakePKCS12(maxPKCS12Bytes))
		}, SecretPKCS12},
		{"remote networks not a list", func(s map[string]any, _ vpn.Secrets) { s[KeyRemoteNetworks] = "10.99.0.0/24" }, KeyRemoteNetworks},
		{"remote network without prefix", func(s map[string]any, _ vpn.Secrets) { s[KeyRemoteNetworks] = []string{"10.99.0.1"} }, KeyRemoteNetworks},
		{"remote network with host bits", func(s map[string]any, _ vpn.Secrets) { s[KeyRemoteNetworks] = []string{"10.99.0.1/24"} }, KeyRemoteNetworks},
		{"remote network with space", func(s map[string]any, _ vpn.Secrets) { s[KeyRemoteNetworks] = []string{" 10.99.0.0/24"} }, KeyRemoteNetworks},
		{"remote network IPv6", func(s map[string]any, _ vpn.Secrets) { s[KeyRemoteNetworks] = []string{"fd00::/64"} }, KeyRemoteNetworks},
		{"remote network everything", func(s map[string]any, _ vpn.Secrets) { s[KeyRemoteNetworks] = []string{"0.0.0.0/0"} }, KeyRemoteNetworks},
		{"remote network twice", func(s map[string]any, _ vpn.Secrets) {
			s[KeyRemoteNetworks] = []string{"10.99.0.0/24", "10.98.0.0/24", "10.99.0.0/24"}
		}, KeyRemoteNetworks},
		{"remote network holds the server", func(s map[string]any, _ vpn.Secrets) {
			s[KeyRemoteHost] = "198.51.100.7"
			s[KeyRemoteNetworks] = []string{"198.51.100.0/24"}
		}, KeyRemoteNetworks},
		{"too many remote networks", func(s map[string]any, _ vpn.Secrets) {
			networks := make([]string, maxRemoteNetworks+1)
			for i := range networks {
				networks[i] = fmt.Sprintf("10.%d.0.0/16", i)
			}
			s[KeyRemoteNetworks] = networks
		}, KeyRemoteNetworks},
		{"unknown setting", func(s map[string]any, _ vpn.Secrets) { s["script"] = "x" }, "script"},
		{"unknown secret", func(_ map[string]any, sec vpn.Secrets) { sec["token"] = "x" }, "token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings, secrets := mdexSettings(), mdexSecrets()
			tt.change(settings, secrets)
			err := Validate(newProfile(t, settings, secrets))
			if !errors.Is(err, domain.ErrValidation) {
				t.Fatalf("Validate error = %v, want a validation error", err)
			}
			if _, ok := validationFields(t, err)[tt.wantField]; !ok {
				t.Errorf("error %v does not name field %q", err, tt.wantField)
			}
			var v *domain.ValidationError
			if errors.As(err, &v) && v.Issues[tt.wantField].Code == "" {
				t.Errorf("field %q has no issue code: %+v", tt.wantField, v.Issues)
			}
		})
	}
}

func TestRemoteNetworkIssueNamesTheFirstProblem(t *testing.T) {
	lan := []netip.Prefix{netip.MustParsePrefix("192.168.2.0/24")}
	settings := mdexSettings()
	settings[KeyRemoteNetworks] = []string{"10.99.0.0/24", "192.168.2.0/25", "10.1.2.3/24"}
	var v *domain.ValidationError
	if !errors.As(ValidateWithLAN(newProfile(t, settings, mdexSecrets()), lan), &v) {
		t.Fatal("want a validation error")
	}
	want := domain.Issue("remote_network_overlaps_lan", "entry", "2", "subnets", "192.168.2.0/24")
	if got := v.Issues[KeyRemoteNetworks]; !reflect.DeepEqual(got, want) {
		t.Errorf("issue = %+v, want %+v", got, want)
	}
	if message := v.Fields[KeyRemoteNetworks]; !strings.Contains(message, "entry 2 ") || !strings.Contains(message, "entry 3 ") {
		t.Errorf("message = %q, want both problems", message)
	}
}

func TestValidateRejectsOtherProtocol(t *testing.T) {
	p := newProfile(t, mdexSettings(), mdexSecrets())
	p.Protocol = "wireguard"
	if _, ok := validationFields(t, Validate(p))["protocol"]; !ok {
		t.Error("wrong protocol accepted")
	}
}

func TestValidateRejectsInvalidJSONTypes(t *testing.T) {
	p := newProfile(t, mdexSettings(), mdexSecrets())
	p.Settings[KeyExtraOptions] = json.RawMessage(`null`)
	if _, ok := validationFields(t, Validate(p))[KeyExtraOptions]; !ok {
		t.Error("null extraOptions accepted")
	}
}

func TestValidateMessagesNeverEchoValues(t *testing.T) {
	const secret = "Hunter2-very-secret"
	settings, secrets := mdexSettings(), mdexSecrets()
	settings[KeyRemoteHost] = secret + " x"
	settings[KeyExtraOptions] = []string{secret + " up"}
	secrets[SecretPassword] = secret + "\n"
	secrets[SecretTLSAuthKey] = secret
	err := Validate(newProfile(t, settings, secrets))
	if err == nil || strings.Contains(err.Error(), "unter2") {
		t.Errorf("Validate error = %v, must exist and not echo values", err)
	}
}

func TestValidateWithLANRejectsOverlappingRemoteNetworks(t *testing.T) {
	lan := []netip.Prefix{netip.MustParsePrefix("192.168.2.0/24"), netip.MustParsePrefix("10.20.0.0/16")}
	tests := []struct {
		networks []string
		wantErr  bool
	}{
		{networks: []string{"10.99.0.0/24", "192.168.3.0/24"}},
		{networks: []string{"192.168.2.128/25"}, wantErr: true},
		{networks: []string{"10.0.0.0/8"}, wantErr: true},
		{networks: []string{"10.99.0.0/24", "10.20.5.0/24"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.networks, ","), func(t *testing.T) {
			settings := mdexSettings()
			settings[KeyRemoteNetworks] = tt.networks
			p := newProfile(t, settings, mdexSecrets())
			if err := Validate(p); err != nil {
				t.Fatalf("Validate without LAN: %v", err)
			}
			err := ValidateWithLAN(p, lan)
			if !tt.wantErr {
				if err != nil {
					t.Errorf("ValidateWithLAN: %v", err)
				}
				return
			}
			if message := validationFields(t, err)[KeyRemoteNetworks]; !strings.Contains(message, "LAN subnet") {
				t.Errorf("remoteNetworks error = %q, want it to name the LAN", message)
			}
		})
	}
}

func TestRemoteNetworks(t *testing.T) {
	settings := mdexSettings()
	settings[KeyRemoteNetworks] = []string{"10.99.0.0/24", "bogus", "192.0.2.0/25", "10.99.0.0/24"}
	got := RemoteNetworks(newProfile(t, settings, nil))
	want := []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24"), netip.MustParsePrefix("192.0.2.0/25")}
	if !slices.Equal(got, want) {
		t.Errorf("RemoteNetworks = %v, want %v", got, want)
	}
	if got := RemoteNetworks(newProfile(t, mdexSettings(), nil)); got != nil {
		t.Errorf("RemoteNetworks without the setting = %v, want none", got)
	}
}
