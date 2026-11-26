package store

import (
	"errors"
	"fmt"
	"testing"

	"tunneldeck/internal/domain"
)

func TestAdminAccountLifecycle(t *testing.T) {
	s, dir := newTestStore(t)
	admin := domain.AdminAccount{Username: "admin", PasswordHash: "$argon2id$v=19$hash"}

	if err := s.CreateAdminAccount(admin); err != nil {
		t.Fatal(err)
	}
	err := s.CreateAdminAccount(domain.AdminAccount{Username: "other", PasswordHash: "x"})
	if !errors.Is(err, domain.ErrSetupAlreadyDone) {
		t.Fatalf("second create err = %v, want ErrSetupAlreadyDone", err)
	}
	got, ok := openTestStore(t, dir, newCipher(t, 1)).AdminAccount()
	if !ok || got != admin {
		t.Fatalf("reloaded admin = %+v, %v", got, ok)
	}

	if err := s.RemoveAdminAccount(); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveAdminAccount(); err != nil {
		t.Fatalf("removing a missing account: %v", err)
	}
	if _, ok := openTestStore(t, dir, newCipher(t, 1)).AdminAccount(); ok {
		t.Fatal("admin account still stored after removal")
	}
}

func TestCreateAdminAccountValidation(t *testing.T) {
	s, _ := newTestStore(t)
	for _, account := range []domain.AdminAccount{{Username: "admin"}, {PasswordHash: "h"}} {
		if err := s.CreateAdminAccount(account); !errors.Is(err, domain.ErrValidation) {
			t.Errorf("CreateAdminAccount(%+v) err = %v, want ErrValidation", account, err)
		}
	}
}

func TestLanguage(t *testing.T) {
	s, dir := newTestStore(t)
	if err := s.SetLanguage(domain.LanguageGerman); err != nil {
		t.Fatal(err)
	}
	if got := openTestStore(t, dir, newCipher(t, 1)).Language(); got != domain.LanguageGerman {
		t.Fatalf("reloaded language = %q", got)
	}
	for _, bad := range []domain.Language{"", "fr", "DE"} {
		if err := s.SetLanguage(bad); !errors.Is(err, domain.ErrValidation) {
			t.Errorf("SetLanguage(%q) err = %v, want ErrValidation", bad, err)
		}
	}
	if got := s.Language(); got != domain.LanguageGerman {
		t.Fatalf("language after rejected changes = %q", got)
	}
}

// hostRule is a valid inbound TCP rule to this device on port.
func hostRule(port int) domain.FirewallRule {
	return domain.FirewallRule{
		Name: fmt.Sprintf("Host port %d/tcp", port), Direction: domain.DirectionInbound, Action: domain.ActionAccept,
		Protocol: domain.ProtocolTCP, Destination: "192.168.1.10",
		DestinationPort: domain.SinglePort(port), Enabled: true,
	}
}

func TestFirewall(t *testing.T) {
	s, dir := newTestStore(t)
	kept := hostRule(161)
	kept.ID = "keep-me"
	firewall := domain.Firewall{
		FirewallSettings: domain.FirewallSettings{DropInvalid: true, PingLimit: true},
		Rules:            []domain.FirewallRule{hostRule(22), kept},
	}
	stored, err := s.SetFirewall(firewall)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Rules[0].ID == "" || stored.Rules[1].ID != "keep-me" {
		t.Fatalf("IDs = %q, %q; want generated and kept", stored.Rules[0].ID, stored.Rules[1].ID)
	}
	if firewall.Rules[0].ID != "" {
		t.Fatal("SetFirewall modified the caller's slice")
	}

	reloaded := openTestStore(t, dir, newCipher(t, 1)).Firewall()
	if reloaded.FirewallSettings != firewall.FirewallSettings || len(reloaded.Rules) != 2 ||
		reloaded.Rules[0] != stored.Rules[0] || reloaded.Rules[1] != stored.Rules[1] {
		t.Fatalf("reloaded firewall = %+v, want %+v", reloaded, stored)
	}

	stored.Rules[0].Name = "changed"
	got := s.Firewall()
	got.Rules[1].Name = "changed"
	if again := s.Firewall(); again.Rules[0].Name == "changed" || again.Rules[1].Name == "changed" {
		t.Fatalf("callers mutated stored rules: %+v", again.Rules)
	}

	if cleared, err := s.SetFirewall(domain.Firewall{}); err != nil || cleared.Rules == nil || len(cleared.Rules) != 0 {
		t.Fatalf("SetFirewall without rules = %#v, %v; want an empty list", cleared, err)
	}
}

func TestFirewallValidation(t *testing.T) {
	s, _ := newTestStore(t)
	valid := domain.Firewall{Rules: []domain.FirewallRule{hostRule(22)}}
	if _, err := s.SetFirewall(valid); err != nil {
		t.Fatal(err)
	}
	unnamed := hostRule(23)
	unnamed.Name = ""
	tests := []struct {
		name  string
		rules []domain.FirewallRule
	}{
		{"duplicate", []domain.FirewallRule{hostRule(22), hostRule(22)}},
		{"no name", []domain.FirewallRule{unnamed}},
		{"bad port", []domain.FirewallRule{hostRule(70000)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := s.SetFirewall(domain.Firewall{Rules: tt.rules}); !errors.Is(err, domain.ErrValidation) {
				t.Fatalf("err = %v, want ErrValidation", err)
			}
		})
	}
	if got := s.Firewall().Rules; len(got) != 1 || got[0].DestinationPort.From != 22 {
		t.Fatalf("rejected changes altered the rules: %+v", got)
	}
}

func TestDesiredConnection(t *testing.T) {
	s, dir := newTestStore(t)
	p := mustCreate(t, s, openVPNProfile("Office"))

	tests := []struct {
		name    string
		desired domain.DesiredConnection
		wantErr error
	}{
		{"connect existing", domain.DesiredConnection{ActiveProfileID: p.ID, WantConnected: true}, nil},
		{"unknown profile", domain.DesiredConnection{ActiveProfileID: "missing"}, domain.ErrNotFound},
		{"want without profile", domain.DesiredConnection{WantConnected: true}, domain.ErrValidation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := s.SetDesiredConnection(tt.desired); !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
	want := domain.DesiredConnection{ActiveProfileID: p.ID, WantConnected: true}
	if got := openTestStore(t, dir, newCipher(t, 1)).DesiredConnection(); got != want {
		t.Fatalf("reloaded desired = %+v, want %+v", got, want)
	}
}

func TestDeleteActiveProfileResetsDesiredConnection(t *testing.T) {
	s, dir := newTestStore(t)
	active := mustCreate(t, s, openVPNProfile("Active"))
	other := mustCreate(t, s, openVPNProfile("Other"))
	desired := domain.DesiredConnection{ActiveProfileID: active.ID, WantConnected: true}
	if err := s.SetDesiredConnection(desired); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteProfile(other.ID); err != nil {
		t.Fatal(err)
	}
	if got := s.DesiredConnection(); got != desired {
		t.Fatalf("deleting another profile changed desired = %+v", got)
	}
	if err := s.DeleteProfile(active.ID); err != nil {
		t.Fatal(err)
	}
	if got := openTestStore(t, dir, newCipher(t, 1)).DesiredConnection(); got != (domain.DesiredConnection{}) {
		t.Fatalf("desired after deleting its profile = %+v, want zero", got)
	}
}

func TestDeleteActiveProfileSettingsWriteFailure(t *testing.T) {
	dir := t.TempDir()
	fsys := &faultyFS{}
	s, err := open(dir, newCipher(t, 1), testDependencies(fsys))
	if err != nil {
		t.Fatal(err)
	}
	active := mustCreate(t, s, openVPNProfile("Active"))
	if err := s.SetDesiredConnection(domain.DesiredConnection{ActiveProfileID: active.ID}); err != nil {
		t.Fatal(err)
	}
	fsys.failStep = "rename"
	if err := s.DeleteProfile(active.ID); !errors.Is(err, errInjected) {
		t.Fatalf("err = %v, want injected failure", err)
	}
	if _, err := s.GetProfile(active.ID); err != nil {
		t.Fatalf("profile gone after failed delete: %v", err)
	}
}

func TestSettingsWriteFailureKeepsState(t *testing.T) {
	dir := t.TempDir()
	fsys := &faultyFS{}
	s, err := open(dir, newCipher(t, 1), testDependencies(fsys))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetLanguage(domain.LanguageGerman); err != nil {
		t.Fatal(err)
	}
	before := string(readFile(t, dir, SettingsFileName))
	fsys.failStep = "sync"

	checks := map[string]func() error{
		"language": func() error { return s.SetLanguage(domain.LanguageEnglish) },
		"admin":    func() error { return s.CreateAdminAccount(domain.AdminAccount{Username: "a", PasswordHash: "h"}) },
		"rules": func() error {
			_, err := s.SetFirewall(domain.Firewall{Rules: []domain.FirewallRule{hostRule(22)}})
			return err
		},
		"desired": func() error { return s.SetDesiredConnection(domain.DesiredConnection{}) },
	}
	for name, change := range checks {
		if err := change(); !errors.Is(err, errInjected) {
			t.Errorf("%s: err = %v, want injected failure", name, err)
		}
	}
	if s.Language() != domain.LanguageGerman || len(s.Firewall().Rules) != 0 {
		t.Fatal("memory changed after failed writes")
	}
	if _, ok := s.AdminAccount(); ok {
		t.Fatal("admin account stored after failed write")
	}
	if after := string(readFile(t, dir, SettingsFileName)); after != before {
		t.Fatal("settings.json changed after failed writes")
	}

	fsys.failStep = ""
	if err := s.CreateAdminAccount(domain.AdminAccount{Username: "a", PasswordHash: "h"}); err != nil {
		t.Fatal(err)
	}
	fsys.failStep = "rename"
	if err := s.RemoveAdminAccount(); !errors.Is(err, errInjected) {
		t.Fatalf("RemoveAdminAccount err = %v, want injected failure", err)
	}
	if _, ok := s.AdminAccount(); !ok {
		t.Fatal("admin account removed from memory after failed write")
	}
}
