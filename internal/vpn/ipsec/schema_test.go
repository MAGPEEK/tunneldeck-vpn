package ipsec

import (
	"slices"
	"testing"

	"tunneldeck/internal/vpn"
)

func TestDescribeIsValid(t *testing.T) {
	if err := Describe().Validate(); err != nil {
		t.Fatalf("schema: %v", err)
	}
}

// TestDescribeCoversEveryKey: the form shows every setting and secret the
// driver accepts, each field once.
func TestDescribeCoversEveryKey(t *testing.T) {
	var settings, secrets []string
	for _, section := range Describe().Sections {
		for _, f := range section.Fields {
			if f.Type == vpn.FieldSecret {
				secrets = append(secrets, f.Key)
			} else {
				settings = append(settings, f.Key)
			}
		}
	}
	if !sameSet(settings, settingKeys) || !sameSet(secrets, secretKeys) {
		t.Errorf("settings %v, secrets %v; want %v and %v", settings, secrets, settingKeys, secretKeys)
	}
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func TestTemplatesPresetTheirProposals(t *testing.T) {
	var template vpn.Field
	for _, section := range Describe().Sections {
		for _, f := range section.Fields {
			if f.Key == KeyTemplate {
				template = f
			}
		}
	}
	if len(template.Options) != len(templates) {
		t.Fatalf("options = %+v", template.Options)
	}
	for _, option := range template.Options {
		ike, esp := templateProposals(Template(option.Value))
		got, _ := option.Presets[KeyIKEProposals].([]string)
		gotESP, _ := option.Presets[KeyESPProposals].([]string)
		if !slices.Equal(got, ike) || !slices.Equal(gotESP, esp) || option.LabelKey != "ipsec.template."+option.Value {
			t.Errorf("option %+v", option)
		}
		wantVersion := string(IKEv2)
		if option.Value == string(TemplateFritzBoxUser) {
			wantVersion = string(IKEv1)
			if option.Presets[KeyAuthMethod] != string(AuthPSK) || option.Presets[KeyMode] != string(ModeVirtualIP) {
				t.Errorf("FRITZ!Box user presets = %v", option.Presets)
			}
		}
		if option.Presets[KeyIKEVersion] != wantVersion {
			t.Errorf("%s presets IKE version %v", option.Value, option.Presets[KeyIKEVersion])
		}
	}
}
