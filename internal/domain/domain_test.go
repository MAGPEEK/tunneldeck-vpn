package domain

import (
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestValidationError(t *testing.T) {
	v := &ValidationError{}
	if v.OrNil() != nil {
		t.Fatal("empty ValidationError must be nil as error")
	}
	v.Add("port", "first")
	v.Add("port", "second")
	v.Add("name", "bad")
	v.Merge("rules[0].", NewValidationError("id", "dup"))
	v.Merge("x.", nil)

	err := v.OrNil()
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("errors.Is(%v, ErrValidation) = false", err)
	}
	want := "validation failed: name: bad; port: first; rules[0].id: dup"
	if err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err.Error(), want)
	}
	var nilV *ValidationError
	if nilV.OrNil() != nil {
		t.Fatal("nil *ValidationError must be nil as error")
	}
}

func TestValidationErrorIssues(t *testing.T) {
	v := &ValidationError{}
	v.Add("plain", "no code")
	v.AddIssue("plain", Issue("required"), "ignored: the first message wins")
	v.AddIssue("name", Issue("too_long", "max", "64"), "must be at most 64 characters")
	v.AddIssue("name", Issue("required"), "ignored")
	v.Merge("rules[1].", NewFieldError("port", Issue("port_out_of_range"), "ports must be between 1 and 65535"))
	v.Merge("rules[2].", NewValidationError("id", "dup"))

	want := map[string]FieldIssue{
		"name":          {Code: "too_long", Params: map[string]string{"max": "64"}},
		"rules[1].port": {Code: "port_out_of_range"},
	}
	if !reflect.DeepEqual(v.Issues, want) {
		t.Errorf("Issues = %+v, want %+v", v.Issues, want)
	}
	if v.Fields["plain"] != "no code" || v.Fields["rules[2].id"] != "dup" || len(v.Fields) != 4 {
		t.Errorf("Fields = %v", v.Fields)
	}
}

func TestNewID(t *testing.T) {
	hex32 := regexp.MustCompile(`^[0-9a-f]{32}$`)
	seen := map[string]bool{}
	for range 100 {
		id := NewID()
		if !hex32.MatchString(id) {
			t.Fatalf("NewID() = %q, want 32 hex characters", id)
		}
		if seen[id] {
			t.Fatalf("NewID() repeated %q", id)
		}
		seen[id] = true
	}
}

func TestLanguageValid(t *testing.T) {
	tests := []struct {
		lang Language
		want bool
	}{
		{LanguageGerman, true},
		{LanguageEnglish, true},
		{"", false},
		{"fr", false},
		{"EN", false},
	}
	for _, tt := range tests {
		if got := tt.lang.Valid(); got != tt.want {
			t.Errorf("Language(%q).Valid() = %v, want %v", tt.lang, got, tt.want)
		}
	}
}

func TestDesiredConnectionValidate(t *testing.T) {
	tests := []struct {
		name    string
		d       DesiredConnection
		wantErr bool
	}{
		{"zero value", DesiredConnection{}, false},
		{"profile without wish", DesiredConnection{ActiveProfileID: "a"}, false},
		{"wanted with profile", DesiredConnection{ActiveProfileID: "a", WantConnected: true}, false},
		{"wanted without profile", DesiredConnection{WantConnected: true}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.d.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateProfileName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"simple", "mdex", false},
		{"one char", "a", false},
		{"64 chars", strings.Repeat("a", 64), false},
		{"64 multibyte chars", strings.Repeat("ä", 64), false},
		{"surrounding spaces trimmed", "  office  ", false},
		{"empty", "", true},
		{"only spaces", "   ", true},
		{"65 chars", strings.Repeat("a", 65), true},
		{"newline inside", "office\nvpn", true},
		{"escape character", "office\x1b[31m", true},
		{"zero width space (Cf)", "office" + string(rune(0x200b)) + "vpn", true},
		{"right-to-left override (Cf)", "office" + string(rune(0x202e)) + "vpn", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProfileName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateProfileName(%q) = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestDailyReconnectValidate(t *testing.T) {
	tests := []struct {
		time    string
		wantErr bool
	}{
		{"04:00", false},
		{"00:00", false},
		{"23:59", false},
		{"24:00", true},
		{"12:60", true},
		{"4:00", true},
		{"04:0", true},
		{"0400", true},
		{"04-00", true},
		{"", true},
		{"ab:cd", true},
		{"04:00 ", true},
	}
	for _, tt := range tests {
		t.Run(tt.time, func(t *testing.T) {
			err := DailyReconnect{Time: tt.time}.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate(%q) = %v, wantErr %v", tt.time, err, tt.wantErr)
			}
		})
	}
	if got := DefaultDailyReconnect(); got.Enabled || got.Time != "04:00" {
		t.Fatalf("DefaultDailyReconnect() = %+v", got)
	}
}

func validProfile() Profile {
	settings := Settings{}
	settings.SetString("remoteHost", "vpn.example.com")
	return Profile{
		Name:           "Office",
		Protocol:       ProtocolOpenVPN,
		Settings:       settings,
		Secrets:        map[string]string{"password": "hunter2"},
		DailyReconnect: DefaultDailyReconnect(),
	}
}

func TestProfileValidate(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(p *Profile)
		wantFields []string
	}{
		{"valid", func(*Profile) {}, nil},
		{"nil settings and secrets", func(p *Profile) { p.Settings = nil; p.Secrets = nil }, nil},
		{"empty name", func(p *Profile) { p.Name = " " }, []string{"name"}},
		{"missing protocol", func(p *Profile) { p.Protocol = "" }, []string{"protocol"}},
		{"empty settings key", func(p *Profile) { p.Settings[""] = json.RawMessage(`1`) }, []string{"settings"}},
		{"invalid settings JSON", func(p *Profile) { p.Settings["port"] = json.RawMessage(`{`) }, []string{"settings.port"}},
		{"empty secret key", func(p *Profile) { p.Secrets[""] = "x" }, []string{"secrets"}},
		{"bad reconnect time", func(p *Profile) { p.DailyReconnect.Time = "25:00" }, []string{"dailyReconnect.time"}},
		{"public IPv4 address", func(p *Profile) { p.PublicAddress = "203.0.113.10" }, nil},
		{"public host name", func(p *Profile) { p.PublicAddress = "vpn.example.com" }, nil},
		{"bad public address", func(p *Profile) { p.PublicAddress = "https://vpn.example.com" }, []string{"publicAddress"}},
		{
			"several problems",
			func(p *Profile) { p.Name = ""; p.Protocol = "" },
			[]string{"name", "protocol"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validProfile()
			tt.mutate(&p)
			assertFields(t, p.Validate(), tt.wantFields)
		})
	}
}

func assertFields(t *testing.T, err error, want []string) {
	t.Helper()
	if want == nil {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	var v *ValidationError
	if !errors.As(err, &v) {
		t.Fatalf("error %v is not a *ValidationError", err)
	}
	if len(v.Fields) != len(want) {
		t.Fatalf("fields = %v, want %v", v.Fields, want)
	}
	for _, field := range want {
		if _, ok := v.Fields[field]; !ok {
			t.Fatalf("fields = %v, missing %q", v.Fields, field)
		}
	}
}

func TestProfileNormalize(t *testing.T) {
	p := Profile{Name: "  Office \t"}
	p.Normalize()
	if p.Name != "Office" {
		t.Errorf("Name = %q, want trimmed", p.Name)
	}
	if p.DailyReconnect.Time != DefaultDailyReconnectTime {
		t.Errorf("DailyReconnect.Time = %q, want default", p.DailyReconnect.Time)
	}
	p.DailyReconnect.Time = "05:30"
	p.Normalize()
	if p.DailyReconnect.Time != "05:30" {
		t.Errorf("Normalize overwrote a set time: %q", p.DailyReconnect.Time)
	}
}

func TestProfilePublicHidesSecrets(t *testing.T) {
	p := validProfile()
	p.Secrets["emptyKey"] = ""
	public := p.Public()

	if got := public.Secrets["password"]; !got.HasValue {
		t.Errorf("password HasValue = false, want true")
	}
	if _, ok := public.Secrets["emptyKey"]; ok {
		t.Errorf("empty secret must be absent from the public view")
	}
	for _, v := range []any{p, public} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "hunter2") {
			t.Fatalf("JSON of %T contains the secret: %s", v, b)
		}
	}

	public.Settings.SetString("remoteHost", "changed")
	if got, _ := p.Settings.String("remoteHost"); got != "vpn.example.com" {
		t.Errorf("Public() shares Settings with the profile")
	}
}

func TestEventKinds(t *testing.T) {
	tests := []struct {
		event Event
		want  EventKind
	}{
		{StateEvent{State: StateConnected}, EventKindState},
		{TrafficEvent{BytesIn: 1}, EventKindTraffic},
		{LogEvent{Level: LogLevelInfo, Text: "x"}, EventKindLog},
		{ChannelEvent{DataCipher: "AES-256-GCM"}, EventKindChannel},
		{PublicIPEvent{PublicIP: "203.0.113.9"}, EventKindPublicIP},
	}
	for _, tt := range tests {
		if got := tt.event.Kind(); got != tt.want {
			t.Errorf("%T.Kind() = %q, want %q", tt.event, got, tt.want)
		}
	}
}
