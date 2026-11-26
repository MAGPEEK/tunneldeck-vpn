package store

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"tunneldeck/internal/domain"
)

func rememberedSession(hash string) domain.RememberedSession {
	created := time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)
	return domain.RememberedSession{
		TokenHash: hash, Username: "admin", CreatedAt: created, LastUsedAt: created.Add(time.Hour), ClientIP: "192.168.1.20",
	}
}

func TestRememberedSessionsRoundTrip(t *testing.T) {
	s, dir := newTestStore(t)
	if got := s.RememberedSessions(); got == nil || len(got) != 0 {
		t.Fatalf("fresh store sessions = %#v, want an empty list", got)
	}
	want := []domain.RememberedSession{rememberedSession("aa"), rememberedSession("bb")}
	if err := s.SetRememberedSessions(want); err != nil {
		t.Fatal(err)
	}
	got := s.RememberedSessions()
	got[0].Username = "changed"
	if !reflect.DeepEqual(s.RememberedSessions(), want) {
		t.Fatal("RememberedSessions returned shared memory")
	}
	if reopened := openTestStore(t, dir, newCipher(t, 1)).RememberedSessions(); !reflect.DeepEqual(reopened, want) {
		t.Fatalf("reopened = %+v, want %+v", reopened, want)
	}
	text := string(readFile(t, dir, SettingsFileName))
	for _, part := range []string{`"tokenHash": "aa"`, `"createdAt": "2026-11-20T08:00:00Z"`, `"lastUsedAt": "2026-11-20T09:00:00Z"`, `"clientIp": "192.168.1.20"`} {
		if !strings.Contains(text, part) {
			t.Errorf("settings.json lacks %s:\n%s", part, text)
		}
	}
}

func TestAdminAccountChangesDropRememberedSessions(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Store) error
	}{
		{"remove", func(s *Store) error { return s.RemoveAdminAccount() }},
		{"remove without account", func(s *Store) error {
			if err := s.RemoveAdminAccount(); err != nil {
				return err
			}
			if err := s.SetRememberedSessions([]domain.RememberedSession{rememberedSession("cc")}); err != nil {
				return err
			}
			return s.RemoveAdminAccount()
		}},
		{"create after reset", func(s *Store) error {
			s.settings.Admin = nil
			return s.CreateAdminAccount(domain.AdminAccount{Username: "other", PasswordHash: "h"})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, dir := newTestStore(t)
			if err := s.CreateAdminAccount(domain.AdminAccount{Username: "admin", PasswordHash: "h"}); err != nil {
				t.Fatal(err)
			}
			if err := s.SetRememberedSessions([]domain.RememberedSession{rememberedSession("aa")}); err != nil {
				t.Fatal(err)
			}
			if err := tt.change(s); err != nil {
				t.Fatal(err)
			}
			if got := s.RememberedSessions(); len(got) != 0 {
				t.Fatalf("sessions after %s = %+v, want none", tt.name, got)
			}
			if got := openTestStore(t, dir, newCipher(t, 1)).RememberedSessions(); len(got) != 0 {
				t.Fatalf("reopened sessions = %+v, want none", got)
			}
		})
	}
}

func TestMigrateSettingsV3ToV4(t *testing.T) {
	doc := decodeDoc(t, `{"language":"de"}`)
	if err := migrateSettingsV3ToV4(doc); err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if want := canonicalJSON(t, `{"language":"de","rememberedSessions":[]}`); string(got) != want {
		t.Fatalf("migrated = %s, want %s", got, want)
	}
}

func TestMigrateSettingsV3File(t *testing.T) {
	dir := t.TempDir()
	v3 := `{"schemaVersion":3,"admin":{"username":"admin","passwordHash":"h"},"language":"de",` +
		`"firewall":{"rules":[]},"desiredConnection":{}}`
	writeFile(t, dir, SettingsFileName, v3)
	s := openTestStore(t, dir, newCipher(t, 1))
	if got := s.RememberedSessions(); got == nil || len(got) != 0 {
		t.Fatalf("migrated sessions = %#v, want an empty list", got)
	}
	if string(readFile(t, dir, SettingsFileName)) != v3 {
		t.Fatal("opening rewrote the file; migrations are written by the next change only")
	}
	if err := s.SetLanguage(domain.LanguageEnglish); err != nil {
		t.Fatal(err)
	}
	written := writtenSettings(t, dir)
	if string(written[schemaVersionKey]) != "5" || string(written["rememberedSessions"]) != "[]" {
		t.Fatalf("written settings = %s", readFile(t, dir, SettingsFileName))
	}
	if admin, ok := s.AdminAccount(); !ok || admin.Username != "admin" {
		t.Fatalf("admin lost: %+v", admin)
	}
}
