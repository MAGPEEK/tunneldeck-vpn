package store

import (
	"fmt"
	"maps"
	"strings"
	"time"

	"tunneldeck/internal/domain"
)

// profilesDocument is the content of profiles.json.
type profilesDocument struct {
	SchemaVersion int             `json:"schemaVersion"`
	Profiles      []profileRecord `json:"profiles"`
}

// profileRecord is a profile as stored: secret values are enc:v1 strings.
type profileRecord struct {
	ID             string                `json:"id"`
	Name           string                `json:"name"`
	Protocol       domain.Protocol       `json:"protocol"`
	Settings       domain.Settings       `json:"settings"`
	Secrets        map[string]string     `json:"secrets"`
	DailyReconnect domain.DailyReconnect `json:"dailyReconnect"`
	CreatedAt      time.Time             `json:"createdAt"`
	UpdatedAt      time.Time             `json:"updatedAt"`
}

func defaultProfiles() profilesDocument {
	return profilesDocument{SchemaVersion: profilesSchemaVersion, Profiles: []profileRecord{}}
}

func (r profileRecord) clone() profileRecord {
	c := r
	c.Settings = r.Settings.Clone()
	c.Secrets = maps.Clone(r.Secrets)
	if c.Secrets == nil {
		c.Secrets = map[string]string{}
	}
	return c
}

func (d profilesDocument) clone() profilesDocument {
	c := profilesDocument{SchemaVersion: d.SchemaVersion, Profiles: make([]profileRecord, len(d.Profiles))}
	for i, r := range d.Profiles {
		c.Profiles[i] = r.clone()
	}
	return c
}

// public returns the client-safe view; stored secrets are never empty, so
// each stored key reports HasValue.
func (r profileRecord) public() domain.PublicProfile {
	return domain.Profile{
		ID:             r.ID,
		Name:           r.Name,
		Protocol:       r.Protocol,
		Settings:       r.Settings,
		Secrets:        r.Secrets,
		DailyReconnect: r.DailyReconnect,
		CreatedAt:      r.CreatedAt,
		UpdatedAt:      r.UpdatedAt,
	}.Public()
}

func (s *Store) loadProfiles() error {
	doc := defaultProfiles()
	if err := s.docs.profiles.load(s.fs, s.dir, &doc); err != nil {
		return err
	}
	doc = doc.clone()
	if err := s.checkSecretsDecrypt(doc); err != nil {
		return err
	}
	s.profiles = doc
	return nil
}

// checkSecretsDecrypt fails early when stored secrets cannot be decrypted,
// typically because the key changed. Errors name the profile and field, never
// the value.
func (s *Store) checkSecretsDecrypt(doc profilesDocument) error {
	for _, r := range doc.Profiles {
		for field, value := range r.Secrets {
			if _, err := s.cipher.Decrypt(value); err != nil {
				return fmt.Errorf("%s: profile %s, secret %q: %w", ProfilesFileName, r.ID, field, err)
			}
		}
	}
	return nil
}

// commitProfiles writes next and, on success, makes it the current state.
// The caller holds s.mu.
func (s *Store) commitProfiles(next profilesDocument) error {
	next.SchemaVersion = profilesSchemaVersion
	if err := s.docs.profiles.save(s.fs, s.dir, next); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	s.profiles = next
	return nil
}

// profileIndex returns the index of the profile with id, or -1. The caller
// holds s.mu.
func (s *Store) profileIndex(id string) int {
	for i, r := range s.profiles.Profiles {
		if r.ID == id {
			return i
		}
	}
	return -1
}

func (s *Store) findProfile(id string) (int, error) {
	i := s.profileIndex(id)
	if i < 0 {
		return -1, fmt.Errorf("store: profile %s: %w", id, domain.ErrNotFound)
	}
	return i, nil
}

// checkNameFree fails with domain.ErrConflict when another profile than
// exceptID already uses name, compared case-insensitively.
func (s *Store) checkNameFree(name, exceptID string) error {
	for _, r := range s.profiles.Profiles {
		if r.ID != exceptID && strings.EqualFold(r.Name, name) {
			return fmt.Errorf("store: profile name %q is already in use: %w", name, domain.ErrConflict)
		}
	}
	return nil
}

// ListProfiles returns all profiles in creation order, secrets reduced to
// hasValue.
func (s *Store) ListProfiles() []domain.PublicProfile {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := make([]domain.PublicProfile, len(s.profiles.Profiles))
	for i, r := range s.profiles.Profiles {
		list[i] = r.public()
	}
	return list
}

// GetProfile returns one profile, secrets reduced to hasValue.
func (s *Store) GetProfile(id string) (domain.PublicProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, err := s.findProfile(id)
	if err != nil {
		return domain.PublicProfile{}, err
	}
	return s.profiles.Profiles[i].public(), nil
}

// ProfileWithSecrets returns one profile with decrypted secrets, for the
// driver. Never hand its Secrets to a client.
func (s *Store) ProfileWithSecrets(id string) (domain.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, err := s.findProfile(id)
	if err != nil {
		return domain.Profile{}, err
	}
	r := s.profiles.Profiles[i]
	secrets, err := s.decryptSecrets(r)
	if err != nil {
		return domain.Profile{}, err
	}
	return domain.Profile{
		ID:             r.ID,
		Name:           r.Name,
		Protocol:       r.Protocol,
		Settings:       r.Settings.Clone(),
		Secrets:        secrets,
		DailyReconnect: r.DailyReconnect,
		CreatedAt:      r.CreatedAt,
		UpdatedAt:      r.UpdatedAt,
	}, nil
}

func (s *Store) decryptSecrets(r profileRecord) (map[string]string, error) {
	secrets := make(map[string]string, len(r.Secrets))
	for field, value := range r.Secrets {
		plaintext, err := s.cipher.Decrypt(value)
		if err != nil {
			return nil, fmt.Errorf("store: profile %s, secret %q: %w", r.ID, field, err)
		}
		secrets[field] = plaintext
	}
	return secrets, nil
}

// CreateProfile validates and stores a new profile. The store assigns ID,
// CreatedAt and UpdatedAt and ignores those fields of p. Secrets with an empty
// value are not stored. A name used by another profile (case-insensitive)
// gives domain.ErrConflict.
func (s *Store) CreateProfile(p domain.Profile) (domain.PublicProfile, error) {
	p.Normalize()
	if err := p.Validate(); err != nil {
		return domain.PublicProfile{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkNameFree(p.Name, ""); err != nil {
		return domain.PublicProfile{}, err
	}
	secrets, err := s.applySecretChanges(nil, p.Secrets, nil)
	if err != nil {
		return domain.PublicProfile{}, err
	}
	now := s.timestamp()
	record := newRecord(p, domain.NewID(), secrets, now, now)
	next := s.profiles.clone()
	next.Profiles = append(next.Profiles, record)
	if err := s.commitProfiles(next); err != nil {
		return domain.PublicProfile{}, err
	}
	return record.public(), nil
}

// UpdateProfile replaces name, settings and daily reconnect of the profile
// p.ID and merges its secrets:
//
//   - a secret with a non-empty value in p.Secrets is replaced;
//   - a secret with an empty value, or absent from p.Secrets, keeps its
//     stored value;
//   - a secret named in clearSecrets is removed (naming it in clearSecrets
//     and giving it a non-empty value at once is a validation error).
//
// An empty p.Protocol keeps the stored protocol; another protocol is a
// validation error because secrets and settings belong to the driver.
func (s *Store) UpdateProfile(p domain.Profile, clearSecrets []string) (domain.PublicProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, err := s.findProfile(p.ID)
	if err != nil {
		return domain.PublicProfile{}, err
	}
	current := s.profiles.Profiles[i]
	if err := prepareUpdate(&p, current, clearSecrets); err != nil {
		return domain.PublicProfile{}, err
	}
	if err := s.checkNameFree(p.Name, p.ID); err != nil {
		return domain.PublicProfile{}, err
	}
	secrets, err := s.applySecretChanges(current.Secrets, p.Secrets, clearSecrets)
	if err != nil {
		return domain.PublicProfile{}, err
	}
	record := newRecord(p, current.ID, secrets, current.CreatedAt, s.timestamp())
	next := s.profiles.clone()
	next.Profiles[i] = record
	if err := s.commitProfiles(next); err != nil {
		return domain.PublicProfile{}, err
	}
	return record.public(), nil
}

// prepareUpdate normalises p and validates it against the stored profile.
func prepareUpdate(p *domain.Profile, current profileRecord, clearSecrets []string) error {
	if p.Protocol == "" {
		p.Protocol = current.Protocol
	}
	p.Normalize()
	if err := p.Validate(); err != nil {
		return err
	}
	v := &domain.ValidationError{}
	if p.Protocol != current.Protocol {
		v.Add("protocol", "cannot be changed")
	}
	for _, field := range clearSecrets {
		if p.Secrets[field] != "" {
			v.Add("secrets."+field, "cannot be replaced and cleared at once")
		}
	}
	return v.OrNil()
}

// applySecretChanges returns the encrypted secrets after removing the
// cleared fields and encrypting every non-empty new value.
func (s *Store) applySecretChanges(stored, updates map[string]string, clearFields []string) (map[string]string, error) {
	result := maps.Clone(stored)
	if result == nil {
		result = map[string]string{}
	}
	for _, field := range clearFields {
		delete(result, field)
	}
	for field, plaintext := range updates {
		if plaintext == "" {
			continue
		}
		encrypted, err := s.cipher.Encrypt(plaintext)
		if err != nil {
			return nil, fmt.Errorf("store: encrypt secret %q: %w", field, err)
		}
		result[field] = encrypted
	}
	return result, nil
}

func newRecord(p domain.Profile, id string, secrets map[string]string, created, updated time.Time) profileRecord {
	return profileRecord{
		ID:             id,
		Name:           p.Name,
		Protocol:       p.Protocol,
		Settings:       p.Settings.Clone(),
		Secrets:        secrets,
		DailyReconnect: p.DailyReconnect,
		CreatedAt:      created,
		UpdatedAt:      updated,
	}
}

// DeleteProfile removes a profile. If the desired connection names it, the
// desired connection is reset first, so it never points at a missing
// profile. Refusing to delete a connected profile is the caller's job.
func (s *Store) DeleteProfile(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, err := s.findProfile(id)
	if err != nil {
		return err
	}
	if s.settings.DesiredConnection.ActiveProfileID == id {
		nextSettings := s.settings.clone()
		nextSettings.DesiredConnection = domain.DesiredConnection{}
		if err := s.commitSettings(nextSettings); err != nil {
			return err
		}
	}
	next := s.profiles.clone()
	next.Profiles = append(next.Profiles[:i], next.Profiles[i+1:]...)
	return s.commitProfiles(next)
}
