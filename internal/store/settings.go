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
	Firewall          firewallRecord           `json:"firewall"`
	DesiredConnection domain.DesiredConnection `json:"desiredConnection"`
	// RemoteAccess was added within schema version 1; files without it get
	// the defaults.
	RemoteAccess remoteAccessRecord `json:"remoteAccess"`
}

// firewallRecord is the firewall as settings.json stores it.
type firewallRecord struct {
	domain.FirewallSettings
	Rules []firewallRuleRecord `json:"rules"`
}

// firewallRuleRecord is a rule plus the marker of a legacy host rule
// (domain.LegacyHostRule), which the domain keeps private: schema 2 stored
// "the host" without an address, and only the running host knows it. The
// next change of the firewall stores plain addresses instead.
type firewallRuleRecord struct {
	domain.FirewallRule
	LegacyHost bool `json:"legacyHost,omitempty"`
}

func newFirewallRecord(f domain.Firewall) firewallRecord {
	record := firewallRecord{FirewallSettings: f.FirewallSettings, Rules: make([]firewallRuleRecord, 0, len(f.Rules))}
	for _, rule := range f.Rules {
		record.Rules = append(record.Rules, firewallRuleRecord{FirewallRule: rule, LegacyHost: rule.IsLegacyHost()})
	}
	return record
}

// firewall returns the domain firewall in a new rule list.
func (r firewallRecord) firewall() domain.Firewall {
	f := domain.Firewall{FirewallSettings: r.FirewallSettings, Rules: make([]domain.FirewallRule, 0, len(r.Rules))}
	for _, record := range r.Rules {
		rule := record.FirewallRule
		if record.LegacyHost {
			rule = domain.LegacyHostRule(rule)
		}
		f.Rules = append(f.Rules, rule)
	}
	return f
}

func defaultSettings() settingsDocument {
	return settingsDocument{
		SchemaVersion: settingsSchemaVersion,
		Language:      domain.DefaultLanguage,
		Firewall:      firewallRecord{FirewallSettings: domain.DefaultFirewallSettings(), Rules: []firewallRuleRecord{}},
		RemoteAccess:  remoteAccessRecord{RemoteAccess: domain.DefaultRemoteAccess()},
	}
}

func (d settingsDocument) clone() settingsDocument {
	c := d
	if d.Admin != nil {
		admin := *d.Admin
		c.Admin = &admin
	}
	c.Firewall.Rules = slices.Clone(d.Firewall.Rules)
	return c
}

// cloneFirewall copies the rule list; a nil list becomes empty.
func cloneFirewall(f domain.Firewall) domain.Firewall {
	f.Rules = slices.Clone(f.Rules)
	if f.Rules == nil {
		f.Rules = []domain.FirewallRule{}
	}
	return f
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
	if err := s.checkRemoteAccess(&doc.RemoteAccess); err != nil {
		return err
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
		return domain.NewFieldError("admin", domain.Issue("required"), "username and password hash are required")
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
		return domain.NewFieldError("language", domain.Issue("one_of", "values", "de, en"), "must be de or en")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.settings.clone()
	next.Language = language
	return s.commitSettings(next)
}

// Firewall returns a copy of the firewall settings and rules.
func (s *Store) Firewall() domain.Firewall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings.Firewall.firewall()
}

// SetFirewall validates and replaces the firewall settings and the whole
// rule list (domain.ValidateFirewallRules). Rules without an ID get a new
// one. It returns what was stored. Checks that need the host (its LAN,
// reserved ports, conflicts on the public address) are the caller's.
func (s *Store) SetFirewall(firewall domain.Firewall) (domain.Firewall, error) {
	if err := domain.ValidateFirewallRules(firewall.Rules); err != nil {
		return domain.Firewall{}, err
	}
	stored := cloneFirewall(firewall)
	for i := range stored.Rules {
		if stored.Rules[i].ID == "" {
			stored.Rules[i].ID = domain.NewID()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.settings.clone()
	next.Firewall = newFirewallRecord(stored)
	if err := s.commitSettings(next); err != nil {
		return domain.Firewall{}, err
	}
	return cloneFirewall(stored), nil
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
