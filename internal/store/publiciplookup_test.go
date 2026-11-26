package store

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
)

func TestPublicIPLookupDefaults(t *testing.T) {
	tests := []struct {
		name string
		file string // "" = no settings file
		want domain.PublicIPLookup
	}{
		{name: "new installation", want: domain.DefaultPublicIPLookup()},
		{name: "schema 4 file", file: `{"schemaVersion":4,"language":"de","firewall":{"rules":[]},"rememberedSessions":[]}`,
			want: domain.DefaultPublicIPLookup()},
		{name: "schema 1 file", file: `{"schemaVersion":1,"language":"en"}`, want: domain.DefaultPublicIPLookup()},
		{name: "schema 5 file switched off", file: `{"schemaVersion":5,"publicIpLookup":{"enabled":false,"url":"https://ifconfig.me/ip"}}`,
			want: domain.PublicIPLookup{URL: "https://ifconfig.me/ip"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.file != "" {
				writeFile(t, dir, SettingsFileName, tt.file)
			}
			if got := openTestStore(t, dir, newCipher(t, 1)).PublicIPLookup(); got != tt.want {
				t.Fatalf("PublicIPLookup = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestPublicIPLookupCorruptedFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, SettingsFileName, `{"schemaVersion":5,"publicIpLookup":{"enabled":true,"url":"ftp://x"}}`)
	if _, err := Open(dir, newCipher(t, 1)); err == nil || !strings.Contains(err.Error(), "publicIpLookup") {
		t.Fatalf("Open = %v, want a corrupted publicIpLookup", err)
	}
}

func TestMigrateSettingsV4ToV5(t *testing.T) {
	doc := decodeDoc(t, `{"language":"de"}`)
	if err := migrateSettingsV4ToV5(doc); err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	want := canonicalJSON(t, `{"language":"de","publicIpLookup":{"enabled":true,"url":"https://api.ipify.org"}}`)
	if string(got) != want {
		t.Fatalf("migrated = %s, want %s", got, want)
	}
}

func TestSetPublicIPLookup(t *testing.T) {
	s, dir := newTestStore(t)
	settings := domain.PublicIPLookup{URL: "https://ifconfig.me/ip"}
	if err := s.SetPublicIPLookup(settings); err != nil {
		t.Fatal(err)
	}
	if got := openTestStore(t, dir, newCipher(t, 1)).PublicIPLookup(); got != settings {
		t.Fatalf("reloaded = %+v, want %+v", got, settings)
	}
	if err := s.SetPublicIPLookup(domain.PublicIPLookup{Enabled: true, URL: "nope"}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("invalid setting err = %v", err)
	}
	if got := s.PublicIPLookup(); got != settings {
		t.Fatalf("setting after a rejected change = %+v", got)
	}
	written := writtenSettings(t, dir)
	if string(written[schemaVersionKey]) != "5" || !strings.Contains(string(written["publicIpLookup"]), "ifconfig.me") {
		t.Fatalf("written settings = %s", readFile(t, dir, SettingsFileName))
	}
}
