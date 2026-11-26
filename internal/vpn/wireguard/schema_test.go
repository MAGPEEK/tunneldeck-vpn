package wireguard

import (
	"slices"
	"testing"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

func TestDescribeCoversEveryKeyOnce(t *testing.T) {
	seen := map[string]vpn.Field{}
	var sections []string
	for _, section := range Describe().Sections {
		sections = append(sections, section.Key)
		if section.LabelKey != "wireguard.section."+section.Key {
			t.Errorf("section %q has label key %q", section.Key, section.LabelKey)
		}
		for _, f := range section.Fields {
			if _, dup := seen[f.Key]; dup {
				t.Errorf("field %q appears twice", f.Key)
			}
			seen[f.Key] = f
			if f.LabelKey != "wireguard."+f.Key {
				t.Errorf("field %q has label key %q", f.Key, f.LabelKey)
			}
		}
	}
	if want := []string{"interface", "peer"}; !slices.Equal(sections, want) {
		t.Errorf("sections = %v, want %v", sections, want)
	}
	for _, key := range settingKeys {
		if f, ok := seen[key]; !ok || f.Type == vpn.FieldSecret {
			t.Errorf("setting %q missing or typed secret", key)
		}
	}
	for _, key := range secretKeys {
		if f, ok := seen[key]; !ok || f.Type != vpn.FieldSecret {
			t.Errorf("secret %q missing or not typed secret", key)
		}
	}
	if len(seen) != len(settingKeys)+len(secretKeys) {
		t.Errorf("schema has %d fields, want %d", len(seen), len(settingKeys)+len(secretKeys))
	}
	if err := Describe().Validate(); err != nil {
		t.Errorf("schema is invalid: %v", err)
	}
}

// TestDescribeDefaultsAreValid fills a profile from the schema's defaults
// plus the required values without one, and expects Validate to accept it.
func TestDescribeDefaultsAreValid(t *testing.T) {
	settings := domain.Settings{}
	for _, section := range Describe().Sections {
		for _, f := range section.Fields {
			switch value := f.Default.(type) {
			case int:
				settings.SetInt(f.Key, value)
			case []string:
				settings.SetStringList(f.Key, value)
			case nil:
			default:
				t.Fatalf("field %q has a default of type %T", f.Key, value)
			}
		}
	}
	if got, _ := settings.StringList(KeyAllowedIPs); !slices.Equal(got, []string{"0.0.0.0/0"}) {
		t.Errorf("default allowed IPs = %v", got)
	}
	settings.SetString(KeyAddress, "10.66.0.2/32")
	settings.SetString(KeyPeerPublicKey, testPeerKey(t))
	settings.SetString(KeyEndpoint, "vpn.example.com")
	p := domain.Profile{
		Protocol: domain.ProtocolWireGuard, Settings: settings,
		Secrets: map[string]string{SecretPrivateKey: testPrivateKey(t)},
	}
	if err := Validate(p); err != nil {
		t.Errorf("Validate = %v", err)
	}
}

// TestDescribeNamesAddons: only the private key carries the key pair addon.
func TestDescribeNamesAddons(t *testing.T) {
	for _, section := range Describe().Sections {
		for _, f := range section.Fields {
			want := ""
			if f.Key == SecretPrivateKey {
				want = "keyPair"
			}
			if f.Addon != want {
				t.Errorf("field %q has addon %q, want %q", f.Key, f.Addon, want)
			}
		}
	}
}
