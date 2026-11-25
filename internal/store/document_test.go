package store

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
)

func TestOpenWithoutFilesUsesDefaults(t *testing.T) {
	s, dir := newTestStore(t)
	if _, ok := s.AdminAccount(); ok {
		t.Error("fresh store has an admin account")
	}
	if got := s.Language(); got != domain.DefaultLanguage {
		t.Errorf("Language() = %q, want default", got)
	}
	if got := s.HostAccessRules(); got == nil || len(got) != 0 {
		t.Errorf("HostAccessRules() = %#v, want empty list", got)
	}
	if got := s.DesiredConnection(); got != (domain.DesiredConnection{}) {
		t.Errorf("DesiredConnection() = %+v, want zero", got)
	}
	if got := s.ListProfiles(); got == nil || len(got) != 0 {
		t.Errorf("ListProfiles() = %#v, want empty list", got)
	}
	assertNoTempFiles(t, dir)
}

func TestOpenRejectsBadFiles(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		content  string
		wantText []string
		wantErr  error
	}{
		{"settings not JSON", SettingsFileName, "{not json", []string{SettingsFileName, "corrupted"}, nil},
		{"profiles not JSON", ProfilesFileName, "", []string{ProfilesFileName, "corrupted"}, nil},
		{"profiles truncated", ProfilesFileName, `{"schemaVersion":1,"profiles":[{"id":`, []string{ProfilesFileName, "corrupted"}, nil},
		{"top-level array", SettingsFileName, `[]`, []string{SettingsFileName, "corrupted"}, nil},
		{"top-level null", SettingsFileName, `null`, []string{SettingsFileName, "corrupted"}, nil},
		{"version not a number", SettingsFileName, `{"schemaVersion":"1"}`, []string{SettingsFileName, "schemaVersion"}, nil},
		{"wrong field type", ProfilesFileName, `{"schemaVersion":1,"profiles":{}}`, []string{ProfilesFileName, "corrupted"}, nil},
		{"unsupported language", SettingsFileName, `{"schemaVersion":1,"language":"fr"}`, []string{SettingsFileName, "language"}, nil},
		{
			"newer settings", SettingsFileName, `{"schemaVersion":2}`,
			[]string{SettingsFileName, "version 2", "up to 1"}, errSchemaTooNew,
		},
		{
			"newer profiles", ProfilesFileName, `{"schemaVersion":7,"profiles":[]}`,
			[]string{ProfilesFileName, "version 7", "up to 1"}, errSchemaTooNew,
		},
		{
			"unversioned without migration", SettingsFileName, `{"language":"en"}`,
			[]string{SettingsFileName, "no migration from schema version 0"}, nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, tt.file, tt.content)

			_, err := open(dir, newCipher(t, 1), testDependencies(osFileSystem{}))
			if err == nil {
				t.Fatal("open succeeded, want an error")
			}
			for _, text := range tt.wantText {
				if !strings.Contains(err.Error(), text) {
					t.Errorf("error %q does not mention %q", err, text)
				}
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("errors.Is(err, %v) = false", tt.wantErr)
			}
			if got := string(readFile(t, dir, tt.file)); got != tt.content {
				t.Errorf("file was modified: %q", got)
			}
		})
	}
}

func TestOpenFileSystemErrors(t *testing.T) {
	for _, step := range []string{"mkdir", "read"} {
		t.Run(step, func(t *testing.T) {
			_, err := open(t.TempDir(), newCipher(t, 1), testDependencies(&faultyFS{failStep: step}))
			if !errors.Is(err, errInjected) {
				t.Fatalf("err = %v, want injected failure", err)
			}
		})
	}
}

func TestMigrationHook(t *testing.T) {
	dir := t.TempDir()
	// A hypothetical version 0 stored the language under "lang".
	writeFile(t, dir, SettingsFileName, `{"lang":"de","hostAccessRules":[]}`)

	var calls int
	deps := testDependencies(osFileSystem{})
	deps.docs.settings.migrations = migrations{
		0: func(doc map[string]json.RawMessage) error {
			calls++
			doc["language"] = doc["lang"]
			delete(doc, "lang")
			return nil
		},
	}
	s, err := open(dir, newCipher(t, 1), deps)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if calls != 1 {
		t.Fatalf("migration ran %d times, want 1", calls)
	}
	if got := s.Language(); got != domain.LanguageGerman {
		t.Fatalf("Language() = %q, want migrated value de", got)
	}

	if err := s.SetLanguage(domain.LanguageEnglish); err != nil {
		t.Fatal(err)
	}
	var written map[string]json.RawMessage
	if err := json.Unmarshal(readFile(t, dir, SettingsFileName), &written); err != nil {
		t.Fatal(err)
	}
	if string(written[schemaVersionKey]) != "1" {
		t.Fatalf("written schemaVersion = %s, want 1", written[schemaVersionKey])
	}
}

func TestMigrationRunsStepsInOrder(t *testing.T) {
	var order []int
	step := func(from int) migration {
		return func(map[string]json.RawMessage) error {
			order = append(order, from)
			return nil
		}
	}
	spec := documentSpec{fileName: "x.json", currentVersion: 3, migrations: migrations{0: step(0), 1: step(1), 2: step(2)}}
	doc := map[string]json.RawMessage{}
	if err := spec.migrate(doc, 1); err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != 1 || order[1] != 2 {
		t.Fatalf("steps ran in order %v, want [1 2]", order)
	}
	if string(doc[schemaVersionKey]) != "3" {
		t.Fatalf("schemaVersion = %s, want 3", doc[schemaVersionKey])
	}
}

func TestMigrationFailure(t *testing.T) {
	dir := t.TempDir()
	content := `{"schemaVersion":0}`
	writeFile(t, dir, ProfilesFileName, content)
	deps := testDependencies(osFileSystem{})
	deps.docs.profiles.migrations = migrations{
		0: func(map[string]json.RawMessage) error { return errInjected },
	}
	_, err := open(dir, newCipher(t, 1), deps)
	if !errors.Is(err, errInjected) || !strings.Contains(err.Error(), "migrate schema version 0 to 1") {
		t.Fatalf("err = %v, want wrapped migration failure", err)
	}
	if got := string(readFile(t, dir, ProfilesFileName)); got != content {
		t.Fatalf("file was modified: %q", got)
	}
}
