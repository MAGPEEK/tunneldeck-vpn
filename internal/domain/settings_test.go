package domain

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestSettingsTypedRoundTrip(t *testing.T) {
	s := Settings{}
	s.SetString("host", "vpn.example.com")
	s.SetInt("port", 1194)
	s.SetBool("float", true)
	s.SetStringList("extra", []string{"nobind", "fast-io"})
	s.SetStringList("none", nil)

	if got, err := s.String("host"); err != nil || got != "vpn.example.com" {
		t.Errorf("String = %q, %v", got, err)
	}
	if got, err := s.Int("port"); err != nil || got != 1194 {
		t.Errorf("Int = %d, %v", got, err)
	}
	if got, err := s.Bool("float"); err != nil || !got {
		t.Errorf("Bool = %v, %v", got, err)
	}
	if got, err := s.StringList("extra"); err != nil || !reflect.DeepEqual(got, []string{"nobind", "fast-io"}) {
		t.Errorf("StringList = %v, %v", got, err)
	}
	if got, err := s.StringList("none"); err != nil || got == nil || len(got) != 0 {
		t.Errorf("StringList(nil list) = %#v, %v; want empty non-nil", got, err)
	}
	if !s.Has("host") || s.Has("missing") {
		t.Errorf("Has reports wrong presence")
	}
}

func TestSettingsAccessorErrors(t *testing.T) {
	s := Settings{
		"text":  json.RawMessage(`"x"`),
		"num":   json.RawMessage(`1.5`),
		"null":  json.RawMessage(`null`),
		"mixed": json.RawMessage(`["a", 1]`),
	}
	tests := []struct {
		name    string
		read    func() error
		wantErr error
	}{
		{"missing string", func() error { _, err := s.String("nope"); return err }, ErrSettingMissing},
		{"missing int", func() error { _, err := s.Int("nope"); return err }, ErrSettingMissing},
		{"string as int", func() error { _, err := s.Int("text"); return err }, ErrSettingWrongType},
		{"fraction as int", func() error { _, err := s.Int("num"); return err }, ErrSettingWrongType},
		{"string as bool", func() error { _, err := s.Bool("text"); return err }, ErrSettingWrongType},
		{"number as string", func() error { _, err := s.String("num"); return err }, ErrSettingWrongType},
		{"string as list", func() error { _, err := s.StringList("text"); return err }, ErrSettingWrongType},
		{"null as list", func() error { _, err := s.StringList("null"); return err }, ErrSettingWrongType},
		{"mixed list", func() error { _, err := s.StringList("mixed"); return err }, ErrSettingWrongType},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.read(); !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestSettingsClone(t *testing.T) {
	var nilSettings Settings
	if c := nilSettings.Clone(); c == nil {
		t.Fatal("Clone of nil must be an empty map")
	}

	s := Settings{"host": json.RawMessage(`"a"`)}
	c := s.Clone()
	c["host"][1] = 'b'
	c.SetInt("port", 1)
	if string(s["host"]) != `"a"` || s.Has("port") {
		t.Fatalf("Clone shares memory with the original: %v", s)
	}
}
