package openvpn

import (
	"slices"
	"strings"
	"testing"

	"tunneldeck/internal/vpn"
)

// modernSettings is a profile that follows current practice: AEAD
// negotiated, no compression, no legacy extras.
func modernSettings() map[string]any {
	return map[string]any{
		KeyRemoteHost: "vpn.example.com",
		KeyAuthMode:   AuthModePassword,
		KeyUsername:   "alice",
		KeyCACert:     testMaterial().caPEM,
	}
}

func with(base map[string]any, key string, value any) map[string]any {
	base[key] = value
	return base
}

func advisoryCodes(advisories []vpn.Advisory) []string {
	codes := make([]string, 0, len(advisories))
	for _, a := range advisories {
		codes = append(codes, a.Code)
	}
	return codes
}

func TestAdvise(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		secrets  vpn.Secrets
		want     []string
	}{
		{
			name:     "mdex profile",
			settings: mdexSettings(),
			secrets:  mdexSecrets(),
			want:     []string{AdvisoryUnencryptedDataChannel, AdvisoryFragmentInUse, AdvisoryNoDCO},
		},
		{name: "current practice", settings: modernSettings(), want: []string{AdvisoryNoDCO}},
		{name: "aead cipher list", settings: with(modernSettings(), KeyCipher, "AES-256-GCM:CHACHA20-POLY1305"), want: []string{AdvisoryNoDCO}},
		{name: "none in a list", settings: with(modernSettings(), KeyCipher, "AES-256-GCM:none"), want: []string{AdvisoryUnencryptedDataChannel, AdvisoryNoDCO}},
		{name: "blowfish", settings: with(modernSettings(), KeyCipher, "BF-CBC"), want: []string{AdvisoryWeakCipher, AdvisoryNoDCO}},
		{name: "cbc in a list", settings: with(modernSettings(), KeyCipher, "AES-256-GCM:AES-256-CBC"), want: []string{AdvisoryWeakCipher, AdvisoryNoDCO}},
		{name: "md5 digest", settings: with(modernSettings(), KeyAuthDigest, "md5"), want: []string{AdvisoryWeakDigest, AdvisoryNoDCO}},
		{name: "sha1 digest", settings: with(modernSettings(), KeyAuthDigest, "SHA1"), want: []string{AdvisoryWeakDigest, AdvisoryNoDCO}},
		{name: "sha256 digest", settings: with(modernSettings(), KeyAuthDigest, "SHA256"), want: []string{AdvisoryNoDCO}},
		{
			name:     "no digest with cbc",
			settings: with(with(modernSettings(), KeyCipher, "AES-128-CBC"), KeyAuthDigest, "none"),
			want:     []string{AdvisoryWeakCipher, AdvisoryWeakDigest, AdvisoryNoDCO},
		},
		{name: "no digest with aead", settings: with(with(modernSettings(), KeyCipher, "AES-256-GCM"), KeyAuthDigest, "none"), want: []string{AdvisoryNoDCO}},
		{name: "lzo setting", settings: with(modernSettings(), KeyCompression, CompressionLZO), want: []string{AdvisoryCompressionEnabled, AdvisoryNoDCO}},
		{name: "compress lz4 extra", settings: with(modernSettings(), KeyExtraOptions, []string{"compress lz4-v2"}), want: []string{AdvisoryCompressionEnabled, AdvisoryNoDCO}},
		{name: "allow-compression yes", settings: with(modernSettings(), KeyExtraOptions, []string{"allow-compression yes"}), want: []string{AdvisoryCompressionEnabled, AdvisoryNoDCO}},
		{name: "compress stub is framing only", settings: with(modernSettings(), KeyExtraOptions, []string{"compress stub-v2"}), want: []string{AdvisoryNoDCO}},
		{name: "tls 1.0 minimum", settings: with(modernSettings(), KeyExtraOptions, []string{"tls-version-min 1.0"}), want: []string{AdvisoryTLSBelow12, AdvisoryNoDCO}},
		{name: "tls 1.1 maximum", settings: with(modernSettings(), KeyExtraOptions, []string{"tls-version-max 1.1"}), want: []string{AdvisoryTLSBelow12, AdvisoryNoDCO}},
		{name: "tls 1.3 minimum", settings: with(modernSettings(), KeyExtraOptions, []string{"tls-version-min 1.3"}), want: []string{AdvisoryNoDCO}},
		{name: "tls-auth key", settings: modernSettings(), secrets: vpn.Secrets{SecretTLSAuthKey: "key"}, want: []string{AdvisoryTLSAuthInsteadOfCrypt, AdvisoryNoDCO}},
		{name: "tls-crypt key", settings: modernSettings(), secrets: vpn.Secrets{SecretTLSCryptKey: "key"}, want: []string{AdvisoryNoDCO}},
		{
			name:     "server usage check off",
			settings: with(modernSettings(), KeyVerifyServerCertUsage, false),
			want:     []string{AdvisoryServerUsageCheckDisabled, AdvisoryNoDCO},
		},
		{name: "fragment", settings: with(modernSettings(), KeyExtraOptions, []string{"fragment 1300"}), want: []string{AdvisoryFragmentInUse, AdvisoryNoDCO}},
		{name: "rejected extra is ignored", settings: with(modernSettings(), KeyExtraOptions, []string{"up /bin/fragment"}), want: []string{AdvisoryNoDCO}},
		{name: "malformed values are ignored", settings: with(with(modernSettings(), KeyCipher, 5), KeyExtraOptions, "fragment 1"), want: []string{AdvisoryNoDCO}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newProfile(t, tt.settings, tt.secrets)
			got := Advise(p.Public())
			if codes := advisoryCodes(got); !slices.Equal(codes, tt.want) {
				t.Errorf("codes = %v, want %v", codes, tt.want)
			}
		})
	}
}

func TestAdviseSeverityAndField(t *testing.T) {
	want := map[string]vpn.Advisory{
		AdvisoryUnencryptedDataChannel:   {Code: AdvisoryUnencryptedDataChannel, Severity: vpn.AdvisoryDanger, Field: KeyCipher},
		AdvisoryWeakCipher:               {Code: AdvisoryWeakCipher, Severity: vpn.AdvisoryWarning, Field: KeyCipher},
		AdvisoryWeakDigest:               {Code: AdvisoryWeakDigest, Severity: vpn.AdvisoryWarning, Field: KeyAuthDigest},
		AdvisoryCompressionEnabled:       {Code: AdvisoryCompressionEnabled, Severity: vpn.AdvisoryWarning, Field: KeyCompression},
		AdvisoryTLSBelow12:               {Code: AdvisoryTLSBelow12, Severity: vpn.AdvisoryWarning, Field: KeyExtraOptions},
		AdvisoryTLSAuthInsteadOfCrypt:    {Code: AdvisoryTLSAuthInsteadOfCrypt, Severity: vpn.AdvisoryInfo, Field: SecretTLSAuthKey},
		AdvisoryServerUsageCheckDisabled: {Code: AdvisoryServerUsageCheckDisabled, Severity: vpn.AdvisoryWarning, Field: KeyVerifyServerCertUsage},
		AdvisoryFragmentInUse:            {Code: AdvisoryFragmentInUse, Severity: vpn.AdvisoryInfo, Field: KeyExtraOptions},
		AdvisoryNoDCO:                    {Code: AdvisoryNoDCO, Severity: vpn.AdvisoryInfo},
	}
	settings := map[string]any{
		KeyRemoteHost: "vpn.example.com", KeyCipher: "none:BF-CBC", KeyAuthDigest: "MD5",
		KeyCompression: CompressionLZO, KeyVerifyServerCertUsage: false,
		KeyExtraOptions: []string{"tls-version-min 1.1", "fragment 1300"},
	}
	p := newProfile(t, settings, vpn.Secrets{SecretTLSAuthKey: "key"})
	got := Advise(p.Public())
	if len(got) != len(want) {
		t.Fatalf("got %d advisories %v, want %d", len(got), advisoryCodes(got), len(want))
	}
	for _, a := range got {
		if a != want[a.Code] {
			t.Errorf("advisory = %+v, want %+v", a, want[a.Code])
		}
	}
}

func TestDriverAdviseDelegates(t *testing.T) {
	p := newProfile(t, mdexSettings(), nil).Public()
	if got := New(Options{DeviceName: "tdvpn0"}).Advise(p); !slices.Equal(advisoryCodes(got), advisoryCodes(Advise(p))) {
		t.Errorf("Driver.Advise = %v", advisoryCodes(got))
	}
}

func TestCurrentPracticeDefaults(t *testing.T) {
	for _, section := range Describe().Sections {
		for _, f := range section.Fields {
			if (f.Key == KeyCipher || f.Key == KeyAuthDigest) && (f.Default != nil || f.Required) {
				t.Errorf("field %s: default %v, required %v; want no default and optional", f.Key, f.Default, f.Required)
			}
		}
	}
	p := newProfile(t, modernSettings(), vpn.Secrets{SecretPassword: "pw"})
	if err := Validate(p); err != nil {
		t.Fatalf("Validate with empty cipher and digest: %v", err)
	}
	config, _, err := Render(p, vpn.Secrets(p.Secrets), testOptions)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, unwanted := range []string{"data-ciphers", "\nauth ", "comp-lzo", "\ncipher "} {
		if strings.Contains(config, unwanted) {
			t.Errorf("config contains %q:\n%s", unwanted, config)
		}
	}
	if !strings.Contains(config, "\ntls-version-min 1.2\n") {
		t.Errorf("config lacks the default tls-version-min 1.2:\n%s", config)
	}
}

func TestRenderTLSVersionDefault(t *testing.T) {
	tests := []struct {
		name   string
		extras []string
		want   int // lines starting with "tls-version-min"
	}{
		{name: "no extras", want: 1},
		{name: "own minimum", extras: []string{"tls-version-min 1.3"}, want: 1},
		{name: "own maximum", extras: []string{"tls-version-max 1.3"}, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := modernSettings()
			if tt.extras != nil {
				settings[KeyExtraOptions] = tt.extras
			}
			config, _, err := Render(newProfile(t, settings, nil), vpn.Secrets{SecretPassword: "pw"}, testOptions)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			if got := strings.Count(config, "\ntls-version-min "); got != tt.want {
				t.Errorf("tls-version-min lines = %d, want %d:\n%s", got, tt.want, config)
			}
		})
	}
}
