package domain

import (
	"strings"
	"time"
	"unicode/utf8"
)

// Profile name limits, counted in characters after trimming.
const (
	ProfileNameMinLength = 1
	ProfileNameMaxLength = 64
)

// DefaultDailyReconnectTime is the preset time of the scheduled reconnect.
const DefaultDailyReconnectTime = "04:00"

// Profile is a driver-independent VPN profile. Protocol-specific values live
// in Settings, secret values in Secrets, both keyed by the field names the
// driver defines.
//
// Secrets is excluded from JSON so a Profile can never leak secrets when it
// is serialised by accident; serialise PublicProfile instead.
type Profile struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Protocol       Protocol          `json:"protocol"`
	Settings       Settings          `json:"settings"`
	Secrets        map[string]string `json:"-"`
	DailyReconnect DailyReconnect    `json:"dailyReconnect"`
	CreatedAt      time.Time         `json:"createdAt"`
	UpdatedAt      time.Time         `json:"updatedAt"`
}

// SecretState tells whether a secret field holds a value, without the value.
type SecretState struct {
	HasValue bool `json:"hasValue"`
}

// PublicProfile is the read model safe to hand to clients: secrets are
// reduced to SecretState. Secret fields without a value are absent.
type PublicProfile struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Protocol       Protocol               `json:"protocol"`
	Settings       Settings               `json:"settings"`
	Secrets        map[string]SecretState `json:"secrets"`
	DailyReconnect DailyReconnect         `json:"dailyReconnect"`
	CreatedAt      time.Time              `json:"createdAt"`
	UpdatedAt      time.Time              `json:"updatedAt"`
}

// Public returns the client-safe view of p. A secret counts as present when
// its value is non-empty; the value itself is dropped. Settings are copied.
func (p Profile) Public() PublicProfile {
	secrets := make(map[string]SecretState, len(p.Secrets))
	for key, value := range p.Secrets {
		if value != "" {
			secrets[key] = SecretState{HasValue: true}
		}
	}
	return PublicProfile{
		ID:             p.ID,
		Name:           p.Name,
		Protocol:       p.Protocol,
		Settings:       p.Settings.Clone(),
		Secrets:        secrets,
		DailyReconnect: p.DailyReconnect,
		CreatedAt:      p.CreatedAt,
		UpdatedAt:      p.UpdatedAt,
	}
}

// Normalize trims the name and fills an empty daily reconnect time with the
// default.
func (p *Profile) Normalize() {
	p.Name = strings.TrimSpace(p.Name)
	if p.DailyReconnect.Time == "" {
		p.DailyReconnect.Time = DefaultDailyReconnectTime
	}
}

// Validate checks the driver-independent rules. Protocol-specific rules are
// the driver's job; name uniqueness is the store's job.
func (p Profile) Validate() error {
	v := &ValidationError{}
	v.Merge("", asValidationError(ValidateProfileName(p.Name)))
	if p.Protocol == "" {
		v.Add("protocol", "is required")
	}
	v.Merge("", p.Settings.validate())
	for key := range p.Secrets {
		if key == "" {
			v.Add("secrets", "keys must not be empty")
		}
	}
	v.Merge("dailyReconnect.", asValidationError(p.DailyReconnect.Validate()))
	return v.OrNil()
}

// ValidateProfileName checks the length of a profile name after trimming.
// It reports the field "name".
func ValidateProfileName(name string) error {
	length := utf8.RuneCountInString(strings.TrimSpace(name))
	if length < ProfileNameMinLength || length > ProfileNameMaxLength {
		return NewValidationError("name", "must be between 1 and 64 characters")
	}
	return nil
}

// DailyReconnect schedules one reconnect per day at Time ("HH:MM", local
// time of the container) while the profile is connected.
type DailyReconnect struct {
	Enabled bool   `json:"enabled"`
	Time    string `json:"time"`
}

// DefaultDailyReconnect returns the preset: off, at 04:00.
func DefaultDailyReconnect() DailyReconnect {
	return DailyReconnect{Enabled: false, Time: DefaultDailyReconnectTime}
}

// Validate checks that Time is a 24-hour "HH:MM" clock time. The time is
// checked even when the schedule is off, because it is stored either way.
func (d DailyReconnect) Validate() error {
	if !isClockTime(d.Time) {
		return NewValidationError("time", "must be a time in HH:MM format (00:00 to 23:59)")
	}
	return nil
}

func isClockTime(s string) bool {
	if len(s) != len("15:04") || s[2] != ':' {
		return false
	}
	_, err := time.Parse("15:04", s)
	return err == nil
}

// asValidationError returns err as *ValidationError, or nil.
func asValidationError(err error) *ValidationError {
	v, _ := err.(*ValidationError)
	return v
}
