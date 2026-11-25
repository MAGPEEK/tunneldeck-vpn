package vpn

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn/vpntest"
)

// waitLimit bounds real-time waits so a broken test fails instead of
// hanging; nothing sleeps.
const waitLimit = 5 * time.Second

const fakeProtocol domain.Protocol = "fake"

const testUIPort = 8194

// fakeStore implements ProfileSource, DesiredStateStore and
// FirewallSource like store.Store does.
type fakeStore struct {
	mu         sync.Mutex
	profiles   map[string]domain.Profile
	desired    domain.DesiredConnection
	firewall   domain.Firewall
	desiredErr error
}

func newFakeStore() *fakeStore {
	s := &fakeStore{
		profiles: map[string]domain.Profile{},
		firewall: domain.Firewall{Rules: []domain.FirewallRule{{ID: "r1", Name: "SSH", Direction: domain.DirectionInbound, Protocol: domain.ProtocolTCP, Destination: domain.FirewallDestination{Kind: domain.DestinationHost}, DestinationPort: domain.SinglePort(22), Enabled: true}}},
	}
	for _, id := range []string{"a", "b"} {
		s.profiles[id] = domain.Profile{
			ID: id, Name: "Profile " + strings.ToUpper(id), Protocol: fakeProtocol,
			Secrets: map[string]string{"password": "pw-" + id}, DailyReconnect: domain.DefaultDailyReconnect(),
		}
	}
	return s
}

func (s *fakeStore) ProfileWithSecrets(id string) (domain.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.profiles[id]
	if !ok {
		return domain.Profile{}, fmt.Errorf("store: profile %s: %w", id, domain.ErrNotFound)
	}
	return p, nil
}

func (s *fakeStore) DesiredConnection() domain.DesiredConnection {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.desired
}

func (s *fakeStore) SetDesiredConnection(d domain.DesiredConnection) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.desiredErr != nil {
		return s.desiredErr
	}
	if _, ok := s.profiles[d.ActiveProfileID]; d.ActiveProfileID != "" && !ok {
		return fmt.Errorf("store: desired connection: %w", domain.ErrNotFound)
	}
	s.desired = d
	return nil
}

func (s *fakeStore) Firewall() domain.Firewall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return domain.Firewall{FirewallSettings: s.firewall.FirewallSettings, Rules: slices.Clone(s.firewall.Rules)}
}

func (s *fakeStore) update(f func(s *fakeStore)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

func (s *fakeStore) setDaily(id string, daily domain.DailyReconnect) {
	s.update(func(s *fakeStore) {
		p := s.profiles[id]
		p.DailyReconnect = daily
		s.profiles[id] = p
	})
}

// fakeGuard records netguard calls as "install", "route <ip>", "clear".
type fakeGuard struct {
	mu         sync.Mutex
	calls      []string
	firewall   domain.Firewall
	uiPort     int
	installErr error
	routeErr   error
	clearErr   error
}

func (g *fakeGuard) InstallFirewall(_ context.Context, firewall domain.Firewall, uiPort int) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls = append(g.calls, "install")
	g.firewall, g.uiPort = firewall, uiPort
	return g.installErr
}

func (g *fakeGuard) RouteThroughTunnel(_ context.Context, vpnIP netip.Addr) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls = append(g.calls, "route "+vpnIP.String())
	return g.routeErr
}

func (g *fakeGuard) ClearTunnelRouting(context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls = append(g.calls, "clear")
	return g.clearErr
}

func (g *fakeGuard) recorded() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.calls)
}

func (g *fakeGuard) set(f func(g *fakeGuard)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	f(g)
}

// scriptedDriver is a scripted Driver.
type scriptedDriver struct {
	events    chan domain.Event
	startErr  error
	stopGate  chan struct{} // when set, Stop waits for it
	stopped   chan struct{} // closed by the first Stop
	closeOnce sync.Once

	mu        sync.Mutex
	profile   domain.Profile
	secrets   Secrets
	stopCalls int
}

func newScriptedDriver() *scriptedDriver {
	return &scriptedDriver{events: make(chan domain.Event, 64), stopped: make(chan struct{})}
}

func (*scriptedDriver) Protocol() domain.Protocol     { return fakeProtocol }
func (*scriptedDriver) Describe() FormSchema          { return FormSchema{} }
func (*scriptedDriver) Validate(domain.Profile) error { return nil }
func (*scriptedDriver) Advise(domain.PublicProfile) []Advisory {
	return nil
}
func (d *scriptedDriver) Events() <-chan domain.Event { return d.events }

func (d *scriptedDriver) Start(_ context.Context, p domain.Profile, s Secrets) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.profile, d.secrets = p, s
	return d.startErr
}

func (d *scriptedDriver) Stop(context.Context) error {
	d.mu.Lock()
	d.stopCalls++
	first := d.stopCalls == 1
	d.mu.Unlock()
	if first {
		close(d.stopped)
	}
	if d.stopGate != nil {
		<-d.stopGate
	}
	return nil
}

func (d *scriptedDriver) emit(events ...domain.Event) {
	for _, e := range events {
		d.events <- e
	}
}

func (d *scriptedDriver) closeEvents() { d.closeOnce.Do(func() { close(d.events) }) }

func (d *scriptedDriver) started() (domain.Profile, Secrets) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.profile, d.secrets
}

func (d *scriptedDriver) awaitStop(t *testing.T) {
	t.Helper()
	select {
	case <-d.stopped:
	case <-time.After(waitLimit):
		t.Fatal("the driver was not stopped")
	}
}

func connectedEvent(ip string) domain.StateEvent {
	return domain.StateEvent{State: domain.StateConnected, VPNIP: ip, Remote: "198.51.100.7:1194"}
}

func errorEvent(code domain.ErrorCode, message string) domain.StateEvent {
	return domain.StateEvent{State: domain.StateError, Code: code, Message: message}
}

// recorder collects the events of one subscription.
type recorder struct {
	mu      sync.Mutex
	events  []domain.Event
	cursor  int
	closed  bool
	changed chan struct{}
}

func record(events <-chan domain.Event) *recorder {
	r := &recorder{changed: make(chan struct{})}
	go func() {
		for e := range events {
			r.update(func() { r.events = append(r.events, e) })
		}
		r.update(func() { r.closed = true })
	}()
	return r
}

func (r *recorder) update(f func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f()
	close(r.changed)
	r.changed = make(chan struct{})
}

// next returns the first event after the cursor that matches, and moves
// the cursor behind it.
func (r *recorder) next(t *testing.T, what string, match func(domain.Event) bool) domain.Event {
	t.Helper()
	deadline := time.After(waitLimit)
	for {
		r.mu.Lock()
		for i := r.cursor; i < len(r.events); i++ {
			if match(r.events[i]) {
				r.cursor = i + 1
				e := r.events[i]
				r.mu.Unlock()
				return e
			}
		}
		closed, changed := r.closed, r.changed
		r.mu.Unlock()
		if closed {
			t.Fatalf("subscription closed while waiting for %s; events: %v", what, r.all())
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("no %s; events: %v", what, r.all())
		}
	}
}

func (r *recorder) all() []domain.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.events)
}

func (r *recorder) waitClosed(t *testing.T) {
	t.Helper()
	deadline := time.After(waitLimit)
	for {
		r.mu.Lock()
		closed, changed := r.closed, r.changed
		r.mu.Unlock()
		if closed {
			return
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatal("subscription not closed")
		}
	}
}

// managerHarness wires a ConnectionManager to fakes.
type managerHarness struct {
	t       *testing.T
	clock   *vpntest.FakeClock
	store   *fakeStore
	guard   *fakeGuard
	m       *ConnectionManager
	events  *recorder
	drivers chan *scriptedDriver
	// prepare adjusts every new driver before the manager uses it.
	prepare func(*scriptedDriver)
	gates   []chan struct{}
}

var defaultStart = time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)

func newManagerHarness(t *testing.T) *managerHarness {
	t.Helper()
	return newManagerHarnessAt(t, defaultStart)
}

func newManagerHarnessAt(t *testing.T, start time.Time) *managerHarness {
	t.Helper()
	h := &managerHarness{
		t:       t,
		clock:   vpntest.NewFakeClock(start),
		store:   newFakeStore(),
		guard:   &fakeGuard{},
		drivers: make(chan *scriptedDriver, 32),
	}
	registry := NewRegistry()
	if err := registry.Register(fakeProtocol, h.newDriver); err != nil {
		t.Fatalf("Register: %v", err)
	}
	h.m = NewConnectionManager(ManagerConfig{
		Registry: registry, Profiles: h.store, Desired: h.store, Firewall: h.store, Guard: h.guard,
		UIPort: testUIPort, Clock: h.clock, Random: func() float64 { return 0.5 },
	})
	events, _ := h.m.Subscribe()
	h.events = record(events)
	t.Cleanup(h.cleanup)
	return h
}

func (h *managerHarness) newDriver() Driver {
	d := newScriptedDriver()
	if h.prepare != nil {
		h.prepare(d)
	}
	h.drivers <- d
	return d
}

func (h *managerHarness) cleanup() {
	for _, gate := range h.gates {
		select {
		case <-gate:
		default:
			close(gate)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), waitLimit)
	defer cancel()
	if err := h.m.Shutdown(ctx); err != nil {
		h.t.Errorf("Shutdown: %v", err)
	}
}

// gate returns a channel that blocks a driver's Stop until it is closed.
func (h *managerHarness) gate() chan struct{} {
	gate := make(chan struct{})
	h.gates = append(h.gates, gate)
	return gate
}

func (h *managerHarness) connect(id string) {
	h.t.Helper()
	if err := h.m.Connect(context.Background(), id); err != nil {
		h.t.Fatalf("Connect(%s): %v", id, err)
	}
}

// nextDriver returns the next driver the manager created, once the
// attempt that created it has finished (Start included).
func (h *managerHarness) nextDriver() *scriptedDriver {
	h.t.Helper()
	select {
	case d := <-h.drivers:
		h.m.Status()
		return d
	case <-time.After(waitLimit):
		h.t.Fatal("no driver was created")
		return nil
	}
}

// advance moves the fake clock once the loop has handled everything it
// was sent, so timers armed by those commands are in place.
func (h *managerHarness) advance(d time.Duration) {
	h.t.Helper()
	h.m.Status()
	h.clock.Advance(d)
}

// assertNoDriver checks that no further driver was created once the loop
// has processed everything queued so far.
func (h *managerHarness) assertNoDriver() {
	h.t.Helper()
	h.m.Status()
	select {
	case <-h.drivers:
		h.t.Fatal("an unexpected driver was created")
	default:
	}
}

// connectUp connects id and reports the driver connected with ip.
func (h *managerHarness) connectUp(id, ip string) *scriptedDriver {
	h.t.Helper()
	h.connect(id)
	d := h.nextDriver()
	d.emit(connectedEvent(ip))
	h.waitState(domain.StateConnected)
	return d
}

func (h *managerHarness) waitState(state domain.ConnectionState) domain.StateEvent {
	h.t.Helper()
	e := h.events.next(h.t, "state "+string(state), func(e domain.Event) bool {
		s, ok := e.(domain.StateEvent)
		return ok && s.State == state
	})
	return e.(domain.StateEvent)
}

func (h *managerHarness) waitLog(text string) domain.LogEvent {
	h.t.Helper()
	e := h.events.next(h.t, "log "+text, func(e domain.Event) bool {
		l, ok := e.(domain.LogEvent)
		return ok && strings.Contains(l.Text, text)
	})
	return e.(domain.LogEvent)
}

// pending returns the scheduled timers once the loop is idle.
func (h *managerHarness) pending() []time.Duration {
	h.t.Helper()
	h.m.Status()
	return h.clock.Pending()
}
