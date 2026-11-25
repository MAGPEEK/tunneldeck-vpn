package store

import (
	"fmt"
	"slices"

	"tunneldeck/internal/domain"
)

// settingsDocument is the content of settings.json.
type settingsDocument struct {
	SchemaVersion     int                      `json:"schemaVersion"`
	Admin             *domain.AdminAccount     `json:"admin"`
	Language          domain.Language          `json:"language"`
	HostAccessRules   []domain.HostAccessRule  `json:"hostAccessRules"`
	DesiredConnection domain.DesiredConnection `json:"desiredConnection"`
}

func defaultSettings() settingsDocument {
	return settingsDocument{
		SchemaVersion:   settingsSchemaVersion,
		Language:        domain.DefaultLanguage,
		HostAccessRules: []domain.HostAccessRule{},
	}
}

func (d settingsDocument) clone() settingsDocument {
	c := d
	if d.Admin != nil {
		admin := *d.Admin
		c.Admin = &admin
	}
	c.HostAccessRules = slices.Clone(d.HostAccessRules)
	if c.HostAccessRules == nil {
		c.HostAccessRules = []domain.HostAccessRule{}
	}
	return c
}

func (s *Store) loadSettings() error {
	doc := defaultSettings()
	if err := s.docs.settings.load(s.fs, s.dir, &doc); err != nil {
		return err
	}
	if doc.Language == "" {
		doc.Language = domain.DefaultLanguage
	}
	if !doc.Language.Valid() {
		return fmt.Errorf("%s is corrupted: unsupported language", SettingsFileName)
	}
	s.settings = doc.clone()
	return nil
}

// commitSettings writes next and, on success, makes it the current state.
// The caller holds s.mu.
func (s *Store) commitSettings(next settingsDocument) error {
	next.SchemaVersion = settingsSchemaVersion
	if err := s.docs.settings.save(s.fs, s.dir, next); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	s.settings = next
	return nil
}

// AdminAccount returns the admin account and whether one exists.
func (s *Store) AdminAccount() (domain.AdminAccount, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settings.Admin == nil {
		return domain.AdminAccount{}, false
	}
	return *s.settings.Admin, true
}

// CreateAdminAccount stores the first admin account. It fails with
// domain.ErrSetupAlreadyDone when an account exists, so concurrent setup
// requests cannot both succeed.
func (s *Store) CreateAdminAccount(account domain.AdminAccount) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settings.Admin != nil {
		return fmt.Errorf("store: create admin account: %w", domain.ErrSetupAlreadyDone)
	}
	if account.Username == "" || account.PasswordHash == "" {
		return domain.NewValidationError("admin", "username and password hash are required")
	}
	next := s.settings.clone()
	next.Admin = &account
	return s.commitSettings(next)
}

// RemoveAdminAccount deletes the admin account (admin reset). Removing a
// missing account is not an error.
func (s *Store) RemoveAdminAccount() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settings.Admin == nil {
		return nil
	}
	next := s.settings.clone()
	next.Admin = nil
	return s.commitSettings(next)
}

// Language returns the default UI language.
func (s *Store) Language() domain.Language {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings.Language
}

// SetLanguage changes the default UI language.
func (s *Store) SetLanguage(language domain.Language) error {
	if !language.Valid() {
		return domain.NewValidationError("language", "must be de or en")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.settings.clone()
	next.Language = language
	return s.commitSettings(next)
}

// HostAccessRules returns a copy of the host-access rules.
func (s *Store) HostAccessRules() []domain.HostAccessRule {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings.clone().HostAccessRules
}

// SetHostAccessRules validates and replaces the whole rule list. Rules
// without an ID get a new one. It returns the stored rules.
func (s *Store) SetHostAccessRules(rules []domain.HostAccessRule) ([]domain.HostAccessRule, error) {
	if err := domain.ValidateHostAccessRules(rules); err != nil {
		return nil, err
	}
	stored := slices.Clone(rules)
	if stored == nil {
		stored = []domain.HostAccessRule{}
	}
	for i := range stored {
		if stored[i].ID == "" {
			stored[i].ID = domain.NewID()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.settings.clone()
	next.HostAccessRules = stored
	if err := s.commitSettings(next); err != nil {
		return nil, err
	}
	return slices.Clone(stored), nil
}

// DesiredConnection returns the persisted desired connection state.
func (s *Store) DesiredConnection() domain.DesiredConnection {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings.DesiredConnection
}

// SetDesiredConnection persists the desired connection state. A non-empty
// ActiveProfileID must name an existing profile (domain.ErrNotFound).
func (s *Store) SetDesiredConnection(desired domain.DesiredConnection) error {
	if err := desired.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if desired.ActiveProfileID != "" && s.profileIndex(desired.ActiveProfileID) < 0 {
		return fmt.Errorf("store: desired connection: profile %s: %w", desired.ActiveProfileID, domain.ErrNotFound)
	}
	next := s.settings.clone()
	next.DesiredConnection = desired
	return s.commitSettings(next)
}
