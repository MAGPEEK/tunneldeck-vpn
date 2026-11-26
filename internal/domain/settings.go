package domain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Errors returned by the typed Settings accessors.
var (
	ErrSettingMissing   = errors.New("setting missing")
	ErrSettingWrongType = errors.New("setting has wrong type")
)

// Settings holds the protocol-specific, non-secret values of a profile as
// raw JSON keyed by field name. The driver of the profile's protocol defines
// the keys; domain knows none of them.
type Settings map[string]json.RawMessage

// Has reports whether key is set.
func (s Settings) Has(key string) bool {
	_, ok := s[key]
	return ok
}

// String returns the string stored under key.
func (s Settings) String(key string) (string, error) {
	var v string
	return v, s.decode(key, &v)
}

// Int returns the integer stored under key.
func (s Settings) Int(key string) (int, error) {
	var v int
	return v, s.decode(key, &v)
}

// Bool returns the boolean stored under key.
func (s Settings) Bool(key string) (bool, error) {
	var v bool
	return v, s.decode(key, &v)
}

// StringList returns the list of strings stored under key. A JSON null
// counts as a wrong type, not as an empty list.
func (s Settings) StringList(key string) ([]string, error) {
	var v []string
	if err := s.decode(key, &v); err != nil {
		return nil, err
	}
	if v == nil {
		return nil, fmt.Errorf("setting %q: %w", key, ErrSettingWrongType)
	}
	return v, nil
}

// SetString stores a string under key.
func (s Settings) SetString(key, value string) { s[key] = mustMarshal(value) }

// SetInt stores an integer under key.
func (s Settings) SetInt(key string, value int) { s[key] = mustMarshal(value) }

// SetBool stores a boolean under key.
func (s Settings) SetBool(key string, value bool) { s[key] = mustMarshal(value) }

// SetStringList stores a list of strings under key. A nil list is stored as
// an empty list.
func (s Settings) SetStringList(key string, value []string) {
	if value == nil {
		value = []string{}
	}
	s[key] = mustMarshal(value)
}

// Clone returns a deep copy. The copy of a nil Settings is an empty map.
func (s Settings) Clone() Settings {
	c := make(Settings, len(s))
	for key, value := range s {
		c[key] = bytes.Clone(value)
	}
	return c
}

func (s Settings) decode(key string, target any) error {
	raw, ok := s[key]
	if !ok {
		return fmt.Errorf("setting %q: %w", key, ErrSettingMissing)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("setting %q: %w", key, ErrSettingWrongType)
	}
	return nil
}

func (s Settings) validate() *ValidationError {
	v := &ValidationError{}
	for key, value := range s {
		switch {
		case key == "":
			v.AddIssue("settings", Issue("keys_empty"), "keys must not be empty")
		case !json.Valid(value):
			v.AddIssue("settings."+key, Issue("invalid_json"), "is not valid JSON")
		}
	}
	return v
}

// mustMarshal encodes the plain values used by the typed setters, which
// cannot fail to marshal.
func mustMarshal(value any) json.RawMessage {
	b, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("domain: marshal %T: %v", value, err))
	}
	return b
}
