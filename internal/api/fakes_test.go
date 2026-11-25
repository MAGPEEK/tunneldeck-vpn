package api

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

// testSecret must never appear in a response other than the import draft.
const testSecret = "s3cr3t-value-never-shown"

const testProtocol domain.Protocol = "fakevpn"

const (
	testCookie = "test_session"
	testToken  = "valid-token"
	testUser   = "admin"
	testUIPort = 8194
)

// fakeAuth has one admin "admin" with password "correct-password" and one
// valid session token.
type fakeAuth struct {
	mu          sync.Mutex
	setupDone   bool
	tokens      map[string]string
	retryAfter  time.Duration // locks logins out when > 0
	loginIP     string
	setupCalled bool
}

func newFakeAuth() *fakeAuth {
	return &fakeAuth{setupDone: true, tokens: map[string]string{testToken: testUser}}
}

func (a *fakeAuth) SetupRequired() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.setupDone
}

func (a *fakeAuth) Setup(_, password string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.setupCalled = true
	if a.setupDone {
		return fmt.Errorf("fake: %w", domain.ErrSetupAlreadyDone)
	}
	if len(password) < 12 {
		return domain.NewValidationError("password", "must be between 12 and 256 characters")
	}
	a.setupDone = true
	return nil
}

func (a *fakeAuth) Login(username, password, clientIP string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.loginIP = clientIP
	if a.retryAfter > 0 {
		return "", &RateLimitError{RetryAfter: a.retryAfter}
	}
	if username != testUser || password != "correct-password" {
		return "", ErrInvalidCredentials
	}
	a.tokens["new-token"] = username
	return "new-token", nil
}

func (a *fakeAuth) Authenticate(token string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	username, ok := a.tokens[token]
	return username, ok
}

func (a *fakeAuth) Logout(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.tokens, token)
}

type fakeCookies struct{}

func (fakeCookies) Set(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: testCookie, Value: token, Path: "/", HttpOnly: true})
}

func (fakeCookies) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: testCookie, Path: "/", MaxAge: -1})
}

func (fakeCookies) Token(r *http.Request) string {
	c, err := r.Cookie(testCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

// fakeProfiles is an in-memory profile store.
type fakeProfiles struct {
	mu       sync.Mutex
	profiles []domain.Profile
	nextID   int
	failNext error
}

func (s *fakeProfiles) add(p domain.Profile) domain.Profile {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	p.ID = fmt.Sprintf("p%d", s.nextID)
	s.profiles = append(s.profiles, p)
	return p
}

func (s *fakeProfiles) index(id string) (int, error) {
	i := slices.IndexFunc(s.profiles, func(p domain.Profile) bool { return p.ID == id })
	if i < 0 {
		return -1, fmt.Errorf("fake: profile %s: %w", id, domain.ErrNotFound)
	}
	return i, nil
}

func (s *fakeProfiles) ListProfiles() []domain.PublicProfile {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := make([]domain.PublicProfile, len(s.profiles))
	for i, p := range s.profiles {
		list[i] = p.Public()
	}
	return list
}

func (s *fakeProfiles) GetProfile(id string) (domain.PublicProfile, error) {
	p, err := s.ProfileWithSecrets(id)
	return p.Public(), err
}

func (s *fakeProfiles) ProfileWithSecrets(id string) (domain.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, err := s.index(id)
	if err != nil {
		return domain.Profile{}, err
	}
	p := s.profiles[i]
	p.Secrets = maps.Clone(p.Secrets)
	return p, nil
}

func (s *fakeProfiles) nameTaken(name, exceptID string) bool {
	return slices.ContainsFunc(s.profiles, func(p domain.Profile) bool {
		return p.ID != exceptID && strings.EqualFold(p.Name, name)
	})
}

func (s *fakeProfiles) CreateProfile(p domain.Profile) (domain.PublicProfile, error) {
	s.mu.Lock()
	if err := s.failNext; err != nil {
		s.failNext = nil
		s.mu.Unlock()
		return domain.PublicProfile{}, err
	}
	taken := s.nameTaken(p.Name, "")
	s.mu.Unlock()
	if taken {
		return domain.PublicProfile{}, fmt.Errorf("fake: name: %w", domain.ErrConflict)
	}
	p.Normalize()
	return s.add(p).Public(), nil
}

func (s *fakeProfiles) UpdateProfile(p domain.Profile, clearSecrets []string) (domain.PublicProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, err := s.index(p.ID)
	if err != nil {
		return domain.PublicProfile{}, err
	}
	if s.nameTaken(p.Name, p.ID) {
		return domain.PublicProfile{}, fmt.Errorf("fake: name: %w", domain.ErrConflict)
	}
	p.Secrets = mergeSecrets(s.profiles[i].Secrets, p.Secrets, clearSecrets)
	p.Normalize()
	s.profiles[i] = p
	return p.Public(), nil
}

func (s *fakeProfiles) DeleteProfile(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, err := s.index(id)
	if err != nil {
		return err
	}
	s.profiles = slices.Delete(s.profiles, i, i+1)
	return nil
}

// fakeDriver requires the setting "host" and the secret "password" and
// always advises "test_advice".
type fakeDriver struct{}

func (fakeDriver) Protocol() domain.Protocol { return testProtocol }

func (fakeDriver) Describe() vpn.FormSchema {
	return vpn.FormSchema{Sections: []vpn.Section{{Key: "server", Fields: []vpn.Field{{Key: "host", Type: vpn.FieldText}}}}}
}

func (fakeDriver) Validate(p domain.Profile) error {
	v := &domain.ValidationError{}
	if host, err := p.Settings.String("host"); err != nil || host == "" {
		v.Add("host", "is required")
	}
	if p.Secrets["password"] == "" {
		v.Add("password", "is required")
	}
	return v.OrNil()
}

func (fakeDriver) Advise(domain.PublicProfile) []vpn.Advisory {
	return []vpn.Advisory{{Code: "test_advice", Severity: vpn.AdvisoryInfo, Field: "host"}}
}

func (fakeDriver) Start(context.Context, domain.Profile, vpn.Secrets) error { return nil }
func (fakeDriver) Stop(context.Context) error                               { return nil }
func (fakeDriver) Events() <-chan domain.Event                              { return nil }

type fakeImporter struct{}

func (fakeImporter) Import(protocol domain.Protocol, text string) (ImportDraft, error) {
	if protocol != testProtocol {
		return ImportDraft{}, fmt.Errorf("fake: %w", domain.ErrNotFound)
	}
	if text == "" {
		return ImportDraft{}, domain.NewValidationError("file", "is empty")
	}
	settings := domain.Settings{}
	settings.SetString("host", "vpn.example.com")
	return ImportDraft{
		Settings: settings,
		Secrets:  map[string]string{"password": testSecret},
		Warnings: []ImportWarning{{Code: "dropped", Severity: "warning", Directive: "up", Line: 3, Message: "dropped"}},
	}, nil
}

// fakeConnection records commands and hands out one event channel per
// subscriber.
type fakeConnection struct {
	mu          sync.Mutex
	status      vpn.Status
	commandErr  error
	commands    []string
	changed     []string
	logs        []domain.LogEvent
	logTail     int
	subscribers []chan domain.Event
	cancelled   int
}

func (c *fakeConnection) record(command string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.commands = append(c.commands, command)
	return c.commandErr
}

func (c *fakeConnection) Connect(_ context.Context, id string) error {
	return c.record("connect " + id)
}
func (c *fakeConnection) Disconnect(context.Context) error { return c.record("disconnect") }
func (c *fakeConnection) Reconnect(context.Context) error  { return c.record("reconnect") }

func (c *fakeConnection) ProfileChanged(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.changed = append(c.changed, id)
}

func (c *fakeConnection) Status() vpn.Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

func (c *fakeConnection) setStatus(s vpn.Status) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status = s
}

func (c *fakeConnection) Logs(tail int) []domain.LogEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logTail = tail
	return c.logs
}

func (c *fakeConnection) Subscribe() (<-chan domain.Event, func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	events := make(chan domain.Event, 8)
	c.subscribers = append(c.subscribers, events)
	return events, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.cancelled++
	}
}

func (c *fakeConnection) subscriber(i int) chan domain.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i >= len(c.subscribers) {
		return nil
	}
	return c.subscribers[i]
}

func (c *fakeConnection) cancelCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cancelled
}

type fakeHostAccess struct {
	mu      sync.Mutex
	rules   []domain.HostAccessRule
	failSet error
}

func (h *fakeHostAccess) HostAccessRules() []domain.HostAccessRule {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.rules)
}

func (h *fakeHostAccess) SetHostAccessRules(rules []domain.HostAccessRule) ([]domain.HostAccessRule, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failSet != nil {
		return nil, h.failSet
	}
	stored := slices.Clone(rules)
	for i := range stored {
		if stored[i].ID == "" {
			stored[i].ID = fmt.Sprintf("r%d", i+1)
		}
	}
	h.rules = stored
	return slices.Clone(stored), nil
}

type fakeFirewall struct {
	mu      sync.Mutex
	err     error
	applied [][]domain.HostAccessRule
	uiPort  int
}

func (f *fakeFirewall) InstallFirewall(_ context.Context, rules []domain.HostAccessRule, uiPort int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, rules)
	f.uiPort = uiPort
	return f.err
}

var errBoom = errors.New("boom: internal detail")
