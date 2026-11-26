package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
	"tunneldeck/internal/vpn/vpntest"
)

const testDevice = "tdvpn0"

var testStart = time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)

// fakeDevice records the UAPI operations and keepalives and reports the
// server's handshake and counters as set by the test.
type fakeDevice struct {
	mu         sync.Mutex
	name       string
	mtu        int
	peer       Key
	sets       []string
	keepalives int
	stats      peerStats
	getErr     error
	setErr     error
	closed     bool
	done       chan struct{}
	log        DeviceLog
}

func (f *fakeDevice) IpcSet(config string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets = append(f.sets, config)
	return f.setErr
}

func (f *fakeDevice) IpcGet() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return "", f.getErr
	}
	var seconds, nanos int64
	if !f.stats.lastHandshake.IsZero() {
		seconds, nanos = f.stats.lastHandshake.Unix(), int64(f.stats.lastHandshake.Nanosecond())
	}
	return fmt.Sprintf("private_key=%s\npublic_key=%s\nlast_handshake_time_sec=%d\nlast_handshake_time_nsec=%d\ntx_bytes=%d\nrx_bytes=%d\n",
		strings.Repeat("ab", 32), f.peer.hex(), seconds, nanos, f.stats.txBytes, f.stats.rxBytes), nil
}

func (f *fakeDevice) SendKeepalive(peer Key) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if peer == f.peer {
		f.keepalives++
	}
}

func (f *fakeDevice) Done() <-chan struct{} { return f.done }

func (f *fakeDevice) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		f.log.Verbose("Device closed")
	}
}

func (f *fakeDevice) set(change func(f *fakeDevice)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

func (f *fakeDevice) snapshot() fakeDevice {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fakeDevice{sets: append([]string(nil), f.sets...), keepalives: f.keepalives, closed: f.closed, name: f.name, mtu: f.mtu}
}

// fakeOpener hands out one fakeDevice.
type fakeOpener struct {
	device *fakeDevice
	err    error
	opened int
}

func (o *fakeOpener) Open(name string, mtu int, log DeviceLog) (Device, error) {
	o.opened++
	if o.err != nil {
		return nil, o.err
	}
	o.device.set(func(f *fakeDevice) { f.name, f.mtu, f.log = name, mtu, log })
	return o.device, nil
}

// fakeRunner records commands and fails those that contain failOn.
type fakeRunner struct {
	mu       sync.Mutex
	commands []string
	failOn   string
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	line := strings.Join(append([]string{name}, args...), " ")
	r.commands = append(r.commands, line)
	if r.failOn != "" && strings.Contains(line, r.failOn) {
		return "", errors.New("exit status 2")
	}
	return "", nil
}

// driverHarness runs a Driver against fakes and a fake clock.
type driverHarness struct {
	t        *testing.T
	clock    *vpntest.FakeClock
	device   *fakeDevice
	opener   *fakeOpener
	runner   *fakeRunner
	resolver *fakeResolver
	driver   *Driver
	events   []domain.Event
}

func newDriverHarness(t *testing.T) *driverHarness {
	t.Helper()
	h := &driverHarness{
		t:        t,
		clock:    vpntest.NewFakeClock(testStart),
		device:   &fakeDevice{peer: keyFromHex(t, bobPublicHex), done: make(chan struct{})},
		runner:   &fakeRunner{},
		resolver: &fakeResolver{answers: map[string][]netip.Addr{"vpn.example.com": {netip.MustParseAddr("198.51.100.23")}}},
	}
	h.opener = &fakeOpener{device: h.device}
	h.driver = New(Options{
		DeviceName: testDevice, Runner: h.runner, Opener: h.opener, Resolver: h.resolver, Clock: h.clock,
	})
	t.Cleanup(func() { _ = h.driver.Stop(context.Background()) })
	return h
}

func (h *driverHarness) start(p domain.Profile) error {
	return h.driver.Start(context.Background(), p, vpn.Secrets(p.Secrets))
}

// mustStart starts a valid profile and waits until the setup in the
// background has armed the first check.
func (h *driverHarness) mustStart() {
	h.t.Helper()
	h.mustStartProfile(validProfile(h.t, nil))
}

func (h *driverHarness) mustStartProfile(p domain.Profile) {
	h.t.Helper()
	if err := h.start(p); err != nil {
		h.t.Fatalf("Start: %v", err)
	}
	h.clock.WaitForTimers(h.t, 1)
	h.drain()
}

// failedState waits until Events is closed and returns the last state,
// which must be an error.
func (h *driverHarness) failedState() domain.StateEvent {
	h.t.Helper()
	h.assertEventsClosed()
	got := states(h.taken())
	if len(got) == 0 || got[len(got)-1].State != domain.StateError {
		h.t.Fatalf("states = %+v, want an error last", got)
	}
	return got[len(got)-1]
}

// stopWithin calls Stop and fails the test when it does not return within
// limit.
func (h *driverHarness) stopWithin(limit time.Duration) {
	h.t.Helper()
	stopped := make(chan error, 1)
	go func() { stopped <- h.driver.Stop(context.Background()) }()
	select {
	case err := <-stopped:
		if err != nil {
			h.t.Errorf("Stop = %v", err)
		}
	case <-time.After(limit):
		h.t.Fatalf("Stop did not return within %s", limit)
	}
}

// advance moves the clock poll by poll, reading the events in between so
// that the event buffer never fills.
func (h *driverHarness) advance(d time.Duration) {
	for step := time.Duration(0); step < d; step += pollInterval {
		h.clock.Advance(min(pollInterval, d-step))
		h.drain()
	}
}

func (h *driverHarness) drain() {
	for {
		select {
		case e, ok := <-h.driver.Events():
			if !ok {
				return
			}
			h.events = append(h.events, e)
		default:
			return
		}
	}
}

// taken returns the events read since the last call.
func (h *driverHarness) taken() []domain.Event {
	events := h.events
	h.events = nil
	return events
}

func states(events []domain.Event) []domain.StateEvent {
	var list []domain.StateEvent
	for _, e := range events {
		if s, ok := e.(domain.StateEvent); ok {
			list = append(list, s)
		}
	}
	return list
}

func lastTraffic(events []domain.Event) (domain.TrafficEvent, bool) {
	var last domain.TrafficEvent
	found := false
	for _, e := range events {
		if traffic, ok := e.(domain.TrafficEvent); ok {
			last, found = traffic, true
		}
	}
	return last, found
}

func hasLog(events []domain.Event, part string) bool {
	for _, e := range events {
		if l, ok := e.(domain.LogEvent); ok && strings.Contains(l.Text, part) {
			return true
		}
	}
	return false
}

// handshake makes the fake server answer: a handshake now and some bytes.
func (h *driverHarness) handshake(rx, tx uint64) time.Time {
	at := h.clock.Now()
	h.device.set(func(f *fakeDevice) { f.stats = peerStats{lastHandshake: at, rxBytes: rx, txBytes: tx} })
	return at
}

// sends makes the device report more sent bytes without a new handshake.
func (h *driverHarness) sends(tx uint64) {
	h.device.set(func(f *fakeDevice) { f.stats.txBytes = tx })
}

// assertEventsClosed checks that Events is closed.
func (h *driverHarness) assertEventsClosed() {
	h.t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case e, ok := <-h.driver.Events():
			if !ok {
				return
			}
			h.events = append(h.events, e)
		case <-deadline:
			h.t.Fatal("Events was not closed")
		}
	}
}
