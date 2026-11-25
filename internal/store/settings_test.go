package store

import (
	"errors"
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

func TestHostAccessRules(t *testing.T) {
	s, dir := newTestStore(t)
	rules := []domain.HostAccessRule{
		{Protocol: domain.TransportTCP, Port: 22, Enabled: true, Comment: "ssh"},
		{ID: "keep-me", Protocol: domain.TransportUDP, Port: 161, SourceCIDR: "10.8.0.0/24"},
	}
	stored, err := s.SetHostAccessRules(rules)
	if err != nil {
		t.Fatal(err)
	}
	if stored[0].ID == "" || stored[1].ID != "keep-me" {
		t.Fatalf("IDs = %q, %q; want generated and kept", stored[0].ID, stored[1].ID)
	}
	if rules[0].ID != "" {
		t.Fatal("SetHostAccessRules modified the caller's slice")
	}

	reloaded := openTestStore(t, dir, newCipher(t, 1)).HostAccessRules()
	if len(reloaded) != 2 || reloaded[0] != stored[0] || reloaded[1] != stored[1] {
		t.Fatalf("reloaded rules = %+v, want %+v", reloaded, stored)
	}

	stored[0].Port = 9999
	got := s.HostAccessRules()
	got[1].Port = 9999
	if again := s.HostAccessRules(); again[0].Port != 22 || again[1].Port != 161 {
		t.Fatalf("callers mutated stored rules: %+v", again)
	}

	if cleared, err := s.SetHostAccessRules(nil); err != nil || cleared == nil || len(cleared) != 0 {
		t.Fatalf("SetHostAccessRules(nil) = %#v, %v; want empty list", cleared, err)
	}
}

func TestHostAccessRulesValidation(t *testing.T) {
	s, _ := newTestStore(t)
	valid := []domain.HostAccessRule{{Protocol: domain.TransportTCP, Port: 22}}
	if _, err := s.SetHostAccessRules(valid); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		rules []domain.HostAccessRule
	}{
		{"duplicate", []domain.HostAccessRule{{Protocol: domain.TransportTCP, Port: 22}, {Protocol: domain.TransportTCP, Port: 22}}},
		{"host bits in source", []domain.HostAccessRule{{Protocol: domain.TransportTCP, Port: 22, SourceCIDR: "192.168.1.5/24"}}},
		{"bad port", []domain.HostAccessRule{{Protocol: domain.TransportUDP, Port: 70000}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := s.SetHostAccessRules(tt.rules); !errors.Is(err, domain.ErrValidation) {
				t.Fatalf("err = %v, want ErrValidation", err)
			}
		})
	}
	if got := s.HostAccessRules(); len(got) != 1 || got[0].Port != 22 {
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
			_, err := s.SetHostAccessRules([]domain.HostAccessRule{{Protocol: domain.TransportTCP, Port: 22}})
			return err
		},
		"desired": func() error { return s.SetDesiredConnection(domain.DesiredConnection{}) },
	}
	for name, change := range checks {
		if err := change(); !errors.Is(err, errInjected) {
			t.Errorf("%s: err = %v, want injected failure", name, err)
		}
	}
	if s.Language() != domain.LanguageGerman || len(s.HostAccessRules()) != 0 {
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
