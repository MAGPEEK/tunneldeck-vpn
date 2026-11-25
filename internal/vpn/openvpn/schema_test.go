package openvpn

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"tunneldeck/internal/vpn"
)

func TestDescribeCoversEveryKeyOnce(t *testing.T) {
	seen := map[string]vpn.Field{}
	for _, section := range Describe().Sections {
		for _, f := range section.Fields {
			if _, dup := seen[f.Key]; dup {
				t.Errorf("field %q appears twice", f.Key)
			}
			seen[f.Key] = f
		}
	}
	for key := range settingKeys {
		if f, ok := seen[key]; !ok || f.Type == vpn.FieldSecret {
			t.Errorf("setting %q missing or typed secret", key)
		}
	}
	for key := range secretKeys {
		if f, ok := seen[key]; !ok || f.Type != vpn.FieldSecret {
			t.Errorf("secret %q missing or not typed secret", key)
		}
	}
	if len(seen) != len(settingKeys)+len(secretKeys) {
		t.Errorf("schema has %d fields, want %d", len(seen), len(settingKeys)+len(secretKeys))
	}
}

func TestDescribeFieldsAreConsistent(t *testing.T) {
	schema := Describe()
	sections := make([]string, 0, len(schema.Sections))
	options := map[string][]string{}
	for _, section := range schema.Sections {
		sections = append(sections, section.Key)
		for _, f := range section.Fields {
			if f.LabelKey != "openvpn."+f.Key {
				t.Errorf("field %q has label key %q", f.Key, f.LabelKey)
			}
			for _, o := range f.Options {
				options[f.Key] = append(options[f.Key], o.Value)
				if o.LabelKey != "openvpn."+f.Key+"."+o.Value {
					t.Errorf("option %q of %q has label key %q", o.Value, f.Key, o.LabelKey)
				}
			}
		}
	}
	if want := []string{"server", "authentication", "encryption", "advanced"}; !slices.Equal(sections, want) {
		t.Errorf("sections = %v, want %v", sections, want)
	}
	for _, section := range schema.Sections {
		for _, f := range section.Fields {
			if f.VisibleWhen == nil || f.VisibleWhen.Secret != "" {
				continue
			}
			for _, value := range f.VisibleWhen.Equals {
				if !slices.Contains(options[f.VisibleWhen.Key], value) {
					t.Errorf("field %q is visible for unknown %s %q", f.Key, f.VisibleWhen.Key, value)
				}
			}
		}
	}
	wantOptions := map[string][]string{
		KeyProto: protos, KeyAuthMode: authModes, KeyCompression: compressions, KeyKeyDirection: keyDirections,
	}
	for key, want := range wantOptions {
		if !slices.Equal(options[key], want) {
			t.Errorf("options of %q = %v, want %v", key, options[key], want)
		}
	}
}

func TestDescribeConditionsAreValid(t *testing.T) {
	if err := Describe().Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestOnlyThePKCS12FieldIsBase64Encoded(t *testing.T) {
	for _, section := range Describe().Sections {
		for _, f := range section.Fields {
			want := vpn.FieldEncoding("")
			if f.Key == SecretPKCS12 {
				want = vpn.EncodingBase64
			}
			if f.Encoding != want {
				t.Errorf("field %q encoding = %q, want %q", f.Key, f.Encoding, want)
			}
		}
	}
}

func TestKeyDirectionIsVisibleWithTheTLSAuthKey(t *testing.T) {
	for _, section := range Describe().Sections {
		for _, f := range section.Fields {
			if f.Key != KeyKeyDirection {
				continue
			}
			c := f.VisibleWhen
			if c == nil || c.Secret != SecretTLSAuthKey || c.Key != "" || c.Equals != nil {
				t.Errorf("key direction visibleWhen = %+v, want secret %q", f.VisibleWhen, SecretTLSAuthKey)
			}
			return
		}
	}
	t.Fatal("key direction field missing")
}

func TestDescribeMarshalsToJSON(t *testing.T) {
	b, err := json.Marshal(Describe())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, fragment := range []string{
		`"key":"remoteHost","type":"text","labelKey":"openvpn.remoteHost","required":true`,
		`"key":"port","type":"number","labelKey":"openvpn.port","required":true,"default":1194`,
		`"visibleWhen":{"key":"authMode","equals":["certificate","certificate+password"]}`,
		`"visibleWhen":{"secret":"tlsAuthKey"}`,
		`"key":"verifyServerCertUsage","type":"bool","labelKey":"openvpn.verifyServerCertUsage","default":true`,
		`"key":"extraOptions","type":"stringList"`,
		`"key":"keepalive","type":"text","labelKey":"openvpn.keepalive","placeholder":"10 120"}`,
		`"key":"remoteNetworks","type":"stringList","labelKey":"openvpn.remoteNetworks"`,
		// Certificate and key or a PKCS#12 bundle: none is required alone.
		`"key":"clientCert","type":"textarea","labelKey":"openvpn.clientCert","visibleWhen"`,
		`"key":"clientKey","type":"secret","labelKey":"openvpn.clientKey","multiline":true`,
		`"key":"pkcs12","type":"secret","labelKey":"openvpn.pkcs12","multiline":true`,
	} {
		if !strings.Contains(string(b), fragment) {
			t.Errorf("schema JSON lacks %s", fragment)
		}
	}
}

func TestDescribeReturnsIndependentCopies(t *testing.T) {
	first := Describe()
	first.Sections[1].Fields[1].VisibleWhen.Equals[0] = "changed"
	if Describe().Sections[1].Fields[1].VisibleWhen.Equals[0] == "changed" {
		t.Error("Describe shares state between calls")
	}
}
