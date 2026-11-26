package store

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
)

// openFixture opens a store on a copy of the settings fixture file and
// returns it with its directory and the fixture's content.
func openFixture(t *testing.T, file string) (*Store, string, []byte) {
	t.Helper()
	fixture, err := os.ReadFile(filepath.Join("testdata", file))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFile(t, dir, SettingsFileName, string(fixture))
	return openTestStore(t, dir, newCipher(t, 1)), dir, fixture
}

// assertRules compares rule lists including the private legacy marker.
func assertRules(t *testing.T, got, want []domain.FirewallRule) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("rules = %+v, want %+v", got, want)
	}
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) || got[i].IsLegacyHost() != want[i].IsLegacyHost() {
			t.Errorf("rule %d = %+v (legacy %v), want %+v (legacy %v)",
				i, got[i], got[i].IsLegacyHost(), want[i], want[i].IsLegacyHost())
		}
	}
}

// writtenSettings returns the top-level keys of the settings file in dir.
func writtenSettings(t *testing.T, dir string) map[string]json.RawMessage {
	t.Helper()
	var written map[string]json.RawMessage
	if err := json.Unmarshal(readFile(t, dir, SettingsFileName), &written); err != nil {
		t.Fatal(err)
	}
	return written
}

func TestMigrateSettingsV1Fixture(t *testing.T) {
	s, dir, fixture := openFixture(t, "settings-v1.json")
	want := domain.Firewall{
		FirewallSettings: domain.DefaultFirewallSettings(),
		Rules: []domain.FirewallRule{
			domain.LegacyHostRule(domain.FirewallRule{
				ID: "r-dsm", Name: "Host port 5001/tcp", Action: domain.ActionAccept, Protocol: domain.ProtocolTCP,
				DestinationPort: domain.SinglePort(5001), Enabled: true, Comment: "DSM over HTTPS",
			}),
			domain.LegacyHostRule(domain.FirewallRule{
				ID: "r-snmp", Name: "Host port 161/udp", Action: domain.ActionAccept, Protocol: domain.ProtocolUDP,
				Source: "10.8.0.0/24", DestinationPort: domain.SinglePort(161),
			}),
		},
	}
	got := s.Firewall()
	if got.FirewallSettings != want.FirewallSettings {
		t.Fatalf("migrated settings = %+v, want %+v", got.FirewallSettings, want.FirewallSettings)
	}
	assertRules(t, got.Rules, want.Rules)
	if err := domain.ValidateFirewallRules(got.Rules); err != nil {
		t.Errorf("migrated rules are invalid: %v", err)
	}
	if admin, ok := s.AdminAccount(); !ok || admin.Username != "admin" || s.Language() != domain.LanguageGerman {
		t.Errorf("other settings were lost: admin %+v, language %s", admin, s.Language())
	}
	if string(readFile(t, dir, SettingsFileName)) != string(fixture) {
		t.Fatal("opening rewrote the file; migrations are written by the next change only")
	}

	if err := s.SetLanguage(domain.LanguageEnglish); err != nil {
		t.Fatal(err)
	}
	written := writtenSettings(t, dir)
	if string(written[schemaVersionKey]) != "3" || written["hostAccessRules"] != nil ||
		!strings.Contains(string(written["firewall"]), `"legacyHost": true`) {
		t.Fatalf("written settings keep an old shape: %s", readFile(t, dir, SettingsFileName))
	}
	assertRules(t, openTestStore(t, dir, newCipher(t, 1)).Firewall().Rules, want.Rules)
}

func TestMigrateSettingsV2Fixture(t *testing.T) {
	s, dir, fixture := openFixture(t, "settings-v2.json")
	want := domain.Firewall{
		FirewallSettings: domain.FirewallSettings{DropInvalid: true, SYNFloodProtection: true, PingLimit: true},
		Rules: []domain.FirewallRule{
			domain.LegacyHostRule(domain.FirewallRule{
				ID: "r-ssh", Name: "SSH", Action: domain.ActionAccept, Protocol: domain.ProtocolTCP, Source: "203.0.113.0/24",
				DestinationPort: domain.SinglePort(22), Enabled: true, Comment: "admin access",
			}),
			{
				ID: "r-ike", Name: "Router: IKE", Direction: domain.DirectionInbound, Action: domain.ActionAccept,
				Protocol: domain.ProtocolUDP, Destination: "192.168.1.2", DestinationPort: domain.SinglePort(500),
				PublicPort: domain.SinglePort(500), KeepSourceAddress: true, Enabled: true,
			},
			{
				ID: "r-out", Name: "Router: outbound", Direction: domain.DirectionOutbound, Action: domain.ActionAccept,
				Protocol: domain.ProtocolESP, Source: "192.168.1.2", Destination: "0.0.0.0/0",
			},
		},
	}
	got := s.Firewall()
	if got.FirewallSettings != want.FirewallSettings {
		t.Fatalf("migrated settings = %+v, want %+v", got.FirewallSettings, want.FirewallSettings)
	}
	assertRules(t, got.Rules, want.Rules)
	if err := domain.ValidateFirewallRules(got.Rules); err != nil {
		t.Errorf("migrated rules are invalid: %v", err)
	}
	if string(readFile(t, dir, SettingsFileName)) != string(fixture) {
		t.Fatal("opening rewrote the file; migrations are written by the next change only")
	}

	plain := got
	plain.Rules[0] = plain.Rules[0].WithHostAddress(netip.MustParseAddr("192.168.1.10"))
	if _, err := s.SetFirewall(plain); err != nil {
		t.Fatal(err)
	}
	written := writtenSettings(t, dir)
	if string(written[schemaVersionKey]) != "3" || strings.Contains(string(written["firewall"]), "legacyHost") ||
		strings.Contains(string(written["firewall"]), "kind") {
		t.Fatalf("written firewall keeps a legacy shape: %s", written["firewall"])
	}
	reopened := openTestStore(t, dir, newCipher(t, 1)).Firewall()
	if reopened.Rules[0].IsLegacyHost() || reopened.Rules[0].Destination != "192.168.1.10" {
		t.Fatalf("reopened rule = %+v", reopened.Rules[0])
	}
}

func TestMigrateSettingsV1ToV2(t *testing.T) {
	tests := []struct {
		name      string
		doc       string
		wantRules int
		wantErr   string
	}{
		{name: "no rules key", doc: `{}`},
		{name: "null rules", doc: `{"hostAccessRules":null}`},
		{name: "empty rules", doc: `{"hostAccessRules":[]}`},
		{name: "one rule", doc: `{"hostAccessRules":[{"protocol":"tcp","port":22,"enabled":true}]}`, wantRules: 1},
		{name: "rules not a list", doc: `{"hostAccessRules":{}}`, wantErr: "hostAccessRules"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := decodeDoc(t, tt.doc)
			err := migrateSettingsV1ToV2(doc)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := doc["hostAccessRules"]; ok {
				t.Error("hostAccessRules is still present")
			}
			var firewall firewallV2
			if err := json.Unmarshal(doc["firewall"], &firewall); err != nil {
				t.Fatal(err)
			}
			if firewall.Rules == nil || len(firewall.Rules) != tt.wantRules || !firewall.DropInvalid || !firewall.MSSClamp ||
				!firewall.SYNFloodProtection || !firewall.PingLimit {
				t.Fatalf("firewall = %+v, want %d rules and every protection on", firewall, tt.wantRules)
			}
			for _, rule := range firewall.Rules {
				if rule.Destination.Kind != "host" {
					t.Errorf("rule %+v does not go to the host", rule)
				}
			}
		})
	}
}

func TestMigrateSettingsV2ToV3(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		want    string // the firewall object afterwards; "" = unchanged document
		wantErr string
	}{
		{name: "no firewall", doc: `{}`},
		{name: "null firewall", doc: `{"firewall":null}`},
		{name: "no rules", doc: `{"firewall":{"dropInvalid":true}}`},
		{name: "null rules", doc: `{"firewall":{"rules":null}}`, want: `{"rules":null}`},
		{name: "host", doc: `{"firewall":{"rules":[{"name":"a","destination":{"kind":"host"}}]}}`,
			want: `{"rules":[{"destination":"","legacyHost":true,"name":"a"}]}`},
		{name: "address", doc: `{"firewall":{"rules":[{"destination":{"kind":"address","cidr":"192.168.1.2"}}]}}`,
			want: `{"rules":[{"destination":"192.168.1.2"}]}`},
		{name: "single address in CIDR", doc: `{"firewall":{"rules":[{"destination":{"kind":"address","cidr":"192.168.1.2/32"}}]}}`,
			want: `{"rules":[{"destination":"192.168.1.2"}]}`},
		{name: "network", doc: `{"firewall":{"rules":[{"destination":{"kind":"address","cidr":"10.0.0.0/8"}}]}}`,
			want: `{"rules":[{"destination":"10.0.0.0/8"}]}`},
		{name: "no destination", doc: `{"firewall":{"rules":[{"name":"a"}]}}`, want: `{"rules":[{"destination":"","name":"a"}]}`},
		{name: "firewall not an object", doc: `{"firewall":[]}`, wantErr: "firewall"},
		{name: "rules not a list", doc: `{"firewall":{"rules":{}}}`, wantErr: "firewall.rules"},
		{name: "null rule", doc: `{"firewall":{"rules":[null]}}`, wantErr: "firewall.rules[0]"},
		{name: "destination not an object", doc: `{"firewall":{"rules":[{"destination":"x"}]}}`, wantErr: "firewall.rules[0]: destination"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := decodeDoc(t, tt.doc)
			err := migrateSettingsV2ToV3(doc)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			want := tt.doc
			if tt.want != "" {
				want = `{"firewall":` + tt.want + `}`
			}
			if string(got) != canonicalJSON(t, want) {
				t.Errorf("migrated = %s, want %s", got, canonicalJSON(t, want))
			}
		})
	}
}

func decodeDoc(t *testing.T, s string) map[string]json.RawMessage {
	t.Helper()
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// canonicalJSON re-encodes s with sorted keys and no spaces.
func canonicalJSON(t *testing.T, s string) string {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}
