package api

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/remoteaccess"
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
	loginClient LoginClient
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

func (a *fakeAuth) Login(username, password string, client LoginClient) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.loginClient = client
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

func (fakeCookies) Set(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: testCookie, Value: token, Path: "/", HttpOnly: true, Secure: secure})
}

func (fakeCookies) Clear(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: testCookie, Path: "/", MaxAge: -1, Secure: secure})
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
		Warnings: []ImportWarning{
			{Code: "dropped", Severity: "warning", Directive: "up", Line: 3, Message: "dropped"},
			{Code: "file_reference", Severity: "rejected", Directive: "ca", Line: 4, File: "ca.crt", Message: "file"},
		},
		Missing: []string{"username"},
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

// fakeFirewallStore is an in-memory FirewallStore.
type fakeFirewallStore struct {
	mu       sync.Mutex
	firewall domain.Firewall
	failSet  error
}

func (h *fakeFirewallStore) Firewall() domain.Firewall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return cloneTestFirewall(h.firewall)
}

func (h *fakeFirewallStore) SetFirewall(firewall domain.Firewall) (domain.Firewall, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failSet != nil {
		return domain.Firewall{}, h.failSet
	}
	stored := cloneTestFirewall(firewall)
	for i := range stored.Rules {
		if stored.Rules[i].ID == "" {
			stored.Rules[i].ID = fmt.Sprintf("r%d", i+1)
		}
	}
	h.firewall = stored
	return cloneTestFirewall(stored), nil
}

// setRules stores rules directly, bypassing validation.
func (h *fakeFirewallStore) setRules(rules ...domain.FirewallRule) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.firewall.Rules = rules
}

// hostPortRule is an enabled inbound accepting rule to this device.
func hostPortRule(id string, protocol domain.FirewallProtocol, port int) domain.FirewallRule {
	return domain.FirewallRule{
		ID: id, Name: fmt.Sprintf("Host port %d/%s", port, protocol), Direction: domain.DirectionInbound,
		Action: domain.ActionAccept, Protocol: protocol, Destination: testHostNetwork.Address().String(),
		DestinationPort: domain.SinglePort(port), Enabled: true,
	}
}

func cloneTestFirewall(f domain.Firewall) domain.Firewall {
	f.Rules = slices.Clone(f.Rules)
	return f
}

// testHostNetwork is the LAN fakeFirewall reports by default.
var testHostNetwork = domain.HostNetwork{
	Addresses: []netip.Addr{netip.MustParseAddr("192.168.2.10")},
	Subnets:   []netip.Prefix{netip.MustParsePrefix("192.168.2.0/24")},
	IPForward: true,
}

// fakeFirewall records installs; failOnce fails the next one, err every
// one.
type fakeFirewall struct {
	mu          sync.Mutex
	err         error
	failOnce    error
	applied     []domain.Firewall
	uiPort      int
	network     domain.HostNetwork
	networkErr  error
	counters    map[string]domain.RuleCounters
	countersErr error
	// noCounters reports the counters as unavailable.
	noCounters bool
}

func newFakeFirewall() *fakeFirewall {
	return &fakeFirewall{network: testHostNetwork}
}

func (f *fakeFirewall) InstallFirewall(_ context.Context, firewall domain.Firewall, uiPort int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, firewall)
	f.uiPort = uiPort
	if err := f.failOnce; err != nil {
		f.failOnce = nil
		return err
	}
	return f.err
}

func (f *fakeFirewall) HostNetwork(context.Context) (domain.HostNetwork, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.networkErr != nil {
		return domain.HostNetwork{}, f.networkErr
	}
	return f.network, nil
}

func (f *fakeFirewall) RuleCounters(context.Context) (map[string]domain.RuleCounters, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.countersErr != nil {
		return nil, false, f.countersErr
	}
	if f.noCounters {
		return nil, false, nil
	}
	return maps.Clone(f.counters), true, nil
}

// fakeDevices answers GET /api/firewall/devices.
type fakeDevices struct {
	devices []domain.LANDevice
	err     error
}

func (f *fakeDevices) Devices(context.Context) ([]domain.LANDevice, error) {
	return slices.Clone(f.devices), f.err
}

func (f *fakeFirewall) installs() []domain.Firewall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.applied)
}

// fakeRemoteAccess is an in-memory remote-access store; keys are kept to
// prove they never reach a response.
type fakeRemoteAccess struct {
	mu       sync.Mutex
	settings domain.RemoteAccess
	pairs    map[domain.CertificateSource]domain.KeyPair
	failSet  error
}

func newFakeRemoteAccess() *fakeRemoteAccess {
	return &fakeRemoteAccess{settings: domain.DefaultRemoteAccess(), pairs: map[domain.CertificateSource]domain.KeyPair{}}
}

func (f *fakeRemoteAccess) RemoteAccess() domain.RemoteAccess {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.settings
}

func (f *fakeRemoteAccess) SetRemoteAccess(settings domain.RemoteAccess) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failSet != nil {
		return f.failSet
	}
	f.settings = settings
	return nil
}

func (f *fakeRemoteAccess) RemoteAccessCertificate(source domain.CertificateSource) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pair, ok := f.pairs[source]
	return pair.CertificatePEM, ok
}

func (f *fakeRemoteAccess) SetRemoteAccessKeyPair(source domain.CertificateSource, pair domain.KeyPair) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failSet != nil {
		return f.failSet
	}
	f.pairs[source] = pair
	return nil
}

func (f *fakeRemoteAccess) pair(source domain.CertificateSource) (domain.KeyPair, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pair, ok := f.pairs[source]
	return pair, ok
}

// fakeListener records applied settings; failOnce fails the next Apply.
type fakeListener struct {
	mu       sync.Mutex
	applied  []domain.RemoteAccess
	failOnce error
	status   remoteaccess.Status
}

func (l *fakeListener) Apply(_ context.Context, settings domain.RemoteAccess) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.applied = append(l.applied, settings)
	if err := l.failOnce; err != nil {
		l.failOnce = nil
		l.status.LastError = err.Error()
		return err
	}
	l.status = remoteaccess.Status{Listening: settings.Enabled}
	return nil
}

func (l *fakeListener) Status() remoteaccess.Status {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.status
}

func (l *fakeListener) calls() []domain.RemoteAccess {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.applied)
}

var errBoom = errors.New("boom: internal detail")
