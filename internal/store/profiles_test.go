package store

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/secret"
)

func TestCreateProfileRoundTrip(t *testing.T) {
	s, dir := newTestStore(t)
	p := openVPNProfile("  Office  ")
	p.ID = "ignored"
	p.Secrets["tlsCryptKey"] = ""
	created := mustCreate(t, s, p)

	if created.ID == "" || created.ID == "ignored" {
		t.Fatalf("ID = %q, want a generated ID", created.ID)
	}
	if created.Name != "Office" {
		t.Errorf("Name = %q, want trimmed", created.Name)
	}
	if created.DailyReconnect != domain.DefaultDailyReconnect() {
		t.Errorf("DailyReconnect = %+v, want default", created.DailyReconnect)
	}
	if created.CreatedAt.Location() != time.UTC || !created.CreatedAt.Equal(created.UpdatedAt) {
		t.Errorf("timestamps = %v / %v, want equal and UTC", created.CreatedAt, created.UpdatedAt)
	}
	wantSecrets := map[string]domain.SecretState{"password": {HasValue: true}}
	if len(created.Secrets) != 1 || created.Secrets["password"] != wantSecrets["password"] {
		t.Errorf("Secrets = %v, want %v (empty values are not stored)", created.Secrets, wantSecrets)
	}

	reopened := openTestStore(t, dir, newCipher(t, 1))
	full, err := reopened.ProfileWithSecrets(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if full.Secrets["password"] != secretValue || len(full.Secrets) != 1 {
		t.Errorf("decrypted secrets = %v", full.Secrets)
	}
	if port, err := full.Settings.Int("port"); err != nil || port != 1194 {
		t.Errorf("settings port = %d, %v", port, err)
	}
	if !full.CreatedAt.Equal(created.CreatedAt) || full.Name != "Office" {
		t.Errorf("reloaded profile differs: %+v", full)
	}
}

func TestProfilesFileHoldsOnlyEncryptedSecrets(t *testing.T) {
	s, dir := newTestStore(t)
	mustCreate(t, s, openVPNProfile("Office"))

	raw := string(readFile(t, dir, ProfilesFileName))
	assertNoSecret(t, ProfilesFileName, raw)
	var doc struct {
		SchemaVersion int `json:"schemaVersion"`
		Profiles      []struct {
			Secrets   map[string]string `json:"secrets"`
			CreatedAt string            `json:"createdAt"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != 1 {
		t.Errorf("schemaVersion = %d, want 1", doc.SchemaVersion)
	}
	if got := doc.Profiles[0].Secrets["password"]; !strings.HasPrefix(got, secret.Prefix) {
		t.Errorf("stored secret %q lacks %q", got, secret.Prefix)
	}
	if got := doc.Profiles[0].CreatedAt; !strings.HasSuffix(got, "Z") {
		t.Errorf("createdAt %q is not RFC 3339 UTC", got)
	}
}

func TestCreateProfileErrors(t *testing.T) {
	s, _ := newTestStore(t)
	mustCreate(t, s, openVPNProfile("Office"))

	tests := []struct {
		name    string
		profile domain.Profile
		wantErr error
	}{
		{"duplicate name", openVPNProfile("Office"), domain.ErrConflict},
		{"duplicate name other case", openVPNProfile(" oFFICE "), domain.ErrConflict},
		{"empty name", openVPNProfile(" "), domain.ErrValidation},
		{"missing protocol", func() domain.Profile { p := openVPNProfile("x"); p.Protocol = ""; return p }(), domain.ErrValidation},
		{"bad reconnect time", func() domain.Profile {
			p := openVPNProfile("y")
			p.DailyReconnect.Time = "4:00"
			return p
		}(), domain.ErrValidation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.CreateProfile(tt.profile)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			assertNoSecret(t, "error", err.Error())
		})
	}
	if n := len(s.ListProfiles()); n != 1 {
		t.Fatalf("%d profiles stored, want 1", n)
	}
}

func TestCreateProfileEncryptFailure(t *testing.T) {
	dir := t.TempDir()
	s := openTestStore(t, dir, failingCipher{newCipher(t, 1)})
	_, err := s.CreateProfile(openVPNProfile("Office"))
	if !errors.Is(err, errInjected) {
		t.Fatalf("err = %v, want injected failure", err)
	}
	assertNoSecret(t, "error", err.Error())
	if n := len(s.ListProfiles()); n != 0 {
		t.Fatalf("%d profiles stored after failure", n)
	}
}

func TestUpdateProfileSecretRules(t *testing.T) {
	tests := []struct {
		name         string
		secrets      map[string]string
		clearSecrets []string
		want         map[string]string
	}{
		{"absent keeps", map[string]string{}, nil, map[string]string{"password": secretValue, "clientKey": "key-1"}},
		{"nil keeps", nil, nil, map[string]string{"password": secretValue, "clientKey": "key-1"}},
		{"empty keeps", map[string]string{"password": ""}, nil, map[string]string{"password": secretValue, "clientKey": "key-1"}},
		{"value replaces", map[string]string{"password": "new"}, nil, map[string]string{"password": "new", "clientKey": "key-1"}},
		{"new field added", map[string]string{"tlsAuthKey": "ta"}, nil, map[string]string{"password": secretValue, "clientKey": "key-1", "tlsAuthKey": "ta"}},
		{"clear removes", nil, []string{"clientKey"}, map[string]string{"password": secretValue}},
		{"clear with empty value", map[string]string{"clientKey": ""}, []string{"clientKey"}, map[string]string{"password": secretValue}},
		{"clear unknown is no-op", nil, []string{"nope"}, map[string]string{"password": secretValue, "clientKey": "key-1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, dir := newTestStore(t)
			p := openVPNProfile("Office")
			p.Secrets["clientKey"] = "key-1"
			created := mustCreate(t, s, p)

			update := openVPNProfile("Office")
			update.ID = created.ID
			update.Secrets = tt.secrets
			updated, err := s.UpdateProfile(update, tt.clearSecrets)
			if err != nil {
				t.Fatalf("UpdateProfile: %v", err)
			}
			if len(updated.Secrets) != len(tt.want) {
				t.Errorf("public secrets = %v, want keys of %v", updated.Secrets, tt.want)
			}
			full, err := openTestStore(t, dir, newCipher(t, 1)).ProfileWithSecrets(created.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(full.Secrets) != len(tt.want) {
				t.Fatalf("secrets = %v, want %v", full.Secrets, tt.want)
			}
			for k, v := range tt.want {
				if full.Secrets[k] != v {
					t.Errorf("secret %q = %q, want %q", k, full.Secrets[k], v)
				}
			}
		})
	}
}

func TestUpdateProfileFields(t *testing.T) {
	s, _ := newTestStore(t)
	created := mustCreate(t, s, openVPNProfile("Office"))

	update := openVPNProfile(" Home ")
	update.ID = created.ID
	update.Protocol = "" // keeps the stored protocol
	update.Settings = domain.Settings{}
	update.Settings.SetString("remoteHost", "other.example.com")
	update.DailyReconnect = domain.DailyReconnect{Enabled: true, Time: "03:15"}
	updated, err := s.UpdateProfile(update, nil)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Home" || updated.Protocol != domain.ProtocolOpenVPN {
		t.Errorf("name/protocol = %q/%q", updated.Name, updated.Protocol)
	}
	if updated.Settings.Has("port") {
		t.Errorf("settings must be replaced, not merged: %v", updated.Settings)
	}
	if !updated.DailyReconnect.Enabled || updated.DailyReconnect.Time != "03:15" {
		t.Errorf("DailyReconnect = %+v", updated.DailyReconnect)
	}
	if !updated.CreatedAt.Equal(created.CreatedAt) || !updated.UpdatedAt.After(created.UpdatedAt) {
		t.Errorf("timestamps: created %v→%v, updated %v→%v",
			created.CreatedAt, updated.CreatedAt, created.UpdatedAt, updated.UpdatedAt)
	}
	if updated.UpdatedAt.Location() != time.UTC {
		t.Errorf("UpdatedAt %v is not UTC", updated.UpdatedAt)
	}

	// Renaming to the own name in another case is allowed.
	update.Name = "HOME"
	if _, err := s.UpdateProfile(update, nil); err != nil {
		t.Fatalf("rename to own name in other case: %v", err)
	}
}

func TestUpdateProfileErrors(t *testing.T) {
	s, _ := newTestStore(t)
	office := mustCreate(t, s, openVPNProfile("Office"))
	mustCreate(t, s, openVPNProfile("Home"))

	withID := func(mutate func(p *domain.Profile)) domain.Profile {
		p := openVPNProfile("Office")
		p.ID = office.ID
		mutate(&p)
		return p
	}
	tests := []struct {
		name    string
		profile domain.Profile
		clear   []string
		wantErr error
	}{
		{"unknown id", withID(func(p *domain.Profile) { p.ID = "missing" }), nil, domain.ErrNotFound},
		{"name taken", withID(func(p *domain.Profile) { p.Name = "home" }), nil, domain.ErrConflict},
		{"invalid name", withID(func(p *domain.Profile) { p.Name = "" }), nil, domain.ErrValidation},
		{"protocol change", withID(func(p *domain.Profile) { p.Protocol = "wireguard" }), nil, domain.ErrValidation},
		{"set and clear", withID(func(*domain.Profile) {}), []string{"password"}, domain.ErrValidation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.UpdateProfile(tt.profile, tt.clear)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			assertNoSecret(t, "error", err.Error())
		})
	}
	got, _ := s.GetProfile(office.ID)
	if got.Name != "Office" || !got.UpdatedAt.Equal(office.UpdatedAt) {
		t.Fatalf("failed updates changed the profile: %+v", got)
	}
}

func TestUpdateProfileEncryptFailure(t *testing.T) {
	s, _ := newTestStore(t)
	created := mustCreate(t, s, openVPNProfile("Office"))
	s.cipher = failingCipher{newCipher(t, 1)}
	update := openVPNProfile("Office")
	update.ID = created.ID
	if _, err := s.UpdateProfile(update, nil); !errors.Is(err, errInjected) {
		t.Fatalf("err = %v, want injected failure", err)
	}
}

func TestGetAndDeleteProfile(t *testing.T) {
	s, dir := newTestStore(t)
	a := mustCreate(t, s, openVPNProfile("A"))
	b := mustCreate(t, s, openVPNProfile("B"))
	c := mustCreate(t, s, openVPNProfile("C"))

	if got, err := s.GetProfile(b.ID); err != nil || got.Name != "B" {
		t.Fatalf("GetProfile = %+v, %v", got, err)
	}
	if err := s.DeleteProfile(b.ID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{b.ID, "missing"} {
		if _, err := s.GetProfile(id); !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("GetProfile(%s) err = %v, want ErrNotFound", id, err)
		}
		if _, err := s.ProfileWithSecrets(id); !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("ProfileWithSecrets(%s) err = %v, want ErrNotFound", id, err)
		}
		if err := s.DeleteProfile(id); !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("DeleteProfile(%s) err = %v, want ErrNotFound", id, err)
		}
	}
	list := openTestStore(t, dir, newCipher(t, 1)).ListProfiles()
	if len(list) != 2 || list[0].ID != a.ID || list[1].ID != c.ID {
		t.Fatalf("profiles after delete = %+v, want A, C in creation order", list)
	}
}

func TestReadsReturnCopies(t *testing.T) {
	s, _ := newTestStore(t)
	created := mustCreate(t, s, openVPNProfile("Office"))

	list := s.ListProfiles()
	list[0].Settings.SetString("remoteHost", "evil")
	list[0].Secrets["injected"] = domain.SecretState{HasValue: true}
	one, _ := s.GetProfile(created.ID)
	one.Settings.SetString("remoteHost", "evil")
	full, _ := s.ProfileWithSecrets(created.ID)
	full.Settings.SetString("remoteHost", "evil")
	full.Secrets["password"] = "evil"

	again, _ := s.ProfileWithSecrets(created.ID)
	if host, _ := again.Settings.String("remoteHost"); host != "vpn.example.com" {
		t.Errorf("caller mutated stored settings: %q", host)
	}
	if again.Secrets["password"] != secretValue || len(again.Secrets) != 1 {
		t.Errorf("caller mutated stored secrets: %v", again.Secrets)
	}
}

func TestPublicReadModelNeverContainsSecrets(t *testing.T) {
	s, _ := newTestStore(t)
	created := mustCreate(t, s, openVPNProfile("Office"))
	one, err := s.GetProfile(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	for what, v := range map[string]any{"create result": created, "get": one, "list": s.ListProfiles()} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		assertNoSecret(t, what, string(b))
		if !strings.Contains(string(b), `"password":{"hasValue":true}`) {
			t.Errorf("%s JSON lacks hasValue for password: %s", what, b)
		}
	}
}

func TestOpenWithWrongKeyFails(t *testing.T) {
	s, dir := newTestStore(t)
	mustCreate(t, s, openVPNProfile("Office"))
	before := string(readFile(t, dir, ProfilesFileName))

	_, err := open(dir, newCipher(t, 2), testDependencies(osFileSystem{}))
	if !errors.Is(err, secret.ErrWrongKeyOrTampered) {
		t.Fatalf("err = %v, want ErrWrongKeyOrTampered", err)
	}
	assertNoSecret(t, "error", err.Error())
	if !strings.Contains(err.Error(), ProfilesFileName) || !strings.Contains(err.Error(), `"password"`) {
		t.Errorf("error %q should name the file and field", err)
	}
	if after := string(readFile(t, dir, ProfilesFileName)); after != before {
		t.Fatal("profiles.json was modified")
	}
}

func TestOpenWithTamperedSecretFails(t *testing.T) {
	tests := []struct {
		name    string
		replace func(stored string) string
		wantErr error
	}{
		{"flipped character", func(stored string) string {
			body := []byte(strings.TrimPrefix(stored, secret.Prefix))
			if body[10] == 'A' {
				body[10] = 'B'
			} else {
				body[10] = 'A'
			}
			return secret.Prefix + string(body)
		}, secret.ErrWrongKeyOrTampered},
		{"plaintext without prefix", func(string) string { return "plain" }, secret.ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, dir := newTestStore(t)
			created := mustCreate(t, s, openVPNProfile("Office"))
			stored := s.profiles.Profiles[0].Secrets["password"]
			raw := strings.Replace(string(readFile(t, dir, ProfilesFileName)), stored, tt.replace(stored), 1)
			writeFile(t, dir, ProfilesFileName, raw)

			_, err := open(dir, newCipher(t, 1), testDependencies(osFileSystem{}))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), created.ID) {
				t.Errorf("error %q should name the profile", err)
			}
		})
	}
}

func TestProfileWithSecretsDecryptFailure(t *testing.T) {
	s, _ := newTestStore(t)
	created := mustCreate(t, s, openVPNProfile("Office"))
	s.cipher = newCipher(t, 2)
	_, err := s.ProfileWithSecrets(created.ID)
	if !errors.Is(err, secret.ErrWrongKeyOrTampered) {
		t.Fatalf("err = %v, want ErrWrongKeyOrTampered", err)
	}
	assertNoSecret(t, "error", err.Error())
}

func TestFailedWriteKeepsFileAndMemory(t *testing.T) {
	for _, step := range []string{"create", "write", "sync", "close", "rename"} {
		t.Run(step, func(t *testing.T) {
			dir := t.TempDir()
			fsys := &faultyFS{}
			s, err := open(dir, newCipher(t, 1), testDependencies(fsys))
			if err != nil {
				t.Fatal(err)
			}
			created := mustCreate(t, s, openVPNProfile("Office"))
			before := string(readFile(t, dir, ProfilesFileName))

			fsys.failStep = step
			update := openVPNProfile("Renamed")
			update.ID = created.ID
			if _, err := s.UpdateProfile(update, nil); !errors.Is(err, errInjected) {
				t.Fatalf("UpdateProfile err = %v, want injected failure", err)
			}
			if _, err := s.CreateProfile(openVPNProfile("Second")); !errors.Is(err, errInjected) {
				t.Fatalf("CreateProfile err = %v, want injected failure", err)
			}
			if err := s.DeleteProfile(created.ID); !errors.Is(err, errInjected) {
				t.Fatalf("DeleteProfile err = %v, want injected failure", err)
			}

			if after := string(readFile(t, dir, ProfilesFileName)); after != before {
				t.Fatal("profiles.json changed after a failed write")
			}
			assertNoTempFiles(t, dir)
			list := s.ListProfiles()
			if len(list) != 1 || list[0].Name != "Office" {
				t.Fatalf("memory changed after a failed write: %+v", list)
			}
		})
	}
}
