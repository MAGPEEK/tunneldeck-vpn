package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
)

func TestMigrateSettingsV1Fixture(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "settings-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFile(t, dir, SettingsFileName, string(fixture))

	s := openTestStore(t, dir, newCipher(t, 1))
	want := domain.Firewall{
		FirewallSettings: domain.DefaultFirewallSettings(),
		Rules: []domain.FirewallRule{
			{
				ID: "r-dsm", Name: "Host port 5001/tcp", Direction: domain.DirectionInbound, Action: domain.ActionAccept,
				Protocol: domain.ProtocolTCP, Destination: domain.FirewallDestination{Kind: domain.DestinationHost},
				DestinationPort: domain.SinglePort(5001), Enabled: true, Comment: "DSM over HTTPS",
			},
			{
				ID: "r-snmp", Name: "Host port 161/udp", Direction: domain.DirectionInbound, Action: domain.ActionAccept,
				Protocol: domain.ProtocolUDP, Source: "10.8.0.0/24", Destination: domain.FirewallDestination{Kind: domain.DestinationHost},
				DestinationPort: domain.SinglePort(161),
			},
		},
	}
	got := s.Firewall()
	if got.FirewallSettings != want.FirewallSettings || len(got.Rules) != len(want.Rules) {
		t.Fatalf("migrated firewall = %+v, want %+v", got, want)
	}
	for i := range want.Rules {
		if got.Rules[i] != want.Rules[i] {
			t.Errorf("rule %d = %+v, want %+v", i, got.Rules[i], want.Rules[i])
		}
	}
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
	var written map[string]json.RawMessage
	if err := json.Unmarshal(readFile(t, dir, SettingsFileName), &written); err != nil {
		t.Fatal(err)
	}
	if string(written[schemaVersionKey]) != "2" || written["hostAccessRules"] != nil || written["firewall"] == nil {
		t.Fatalf("written settings keep the v1 shape: %s", readFile(t, dir, SettingsFileName))
	}
	if reopened := openTestStore(t, dir, newCipher(t, 1)).Firewall(); len(reopened.Rules) != 2 || reopened.Rules[0] != want.Rules[0] {
		t.Fatalf("reopened firewall = %+v", reopened)
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
			var doc map[string]json.RawMessage
			if err := json.Unmarshal([]byte(tt.doc), &doc); err != nil {
				t.Fatal(err)
			}
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
			var firewall domain.Firewall
			if err := json.Unmarshal(doc["firewall"], &firewall); err != nil {
				t.Fatal(err)
			}
			if firewall.Rules == nil || len(firewall.Rules) != tt.wantRules || firewall.FirewallSettings != domain.DefaultFirewallSettings() {
				t.Fatalf("firewall = %+v, want %d rules and every protection on", firewall, tt.wantRules)
			}
		})
	}
}
