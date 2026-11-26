package vpn

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"tunneldeck/internal/domain"
)

var ctx = context.Background()

func TestManagerConnectAndDisconnect(t *testing.T) {
	h := newManagerHarness(t)
	h.connect("a")
	d := h.nextDriver()
	h.waitState(domain.StateConnecting)
	p, secrets := d.started()
	if p.ID != "a" || secrets["password"] != "pw-a" {
		t.Errorf("driver started with %+v / %v", p, secrets)
	}
	if got := h.store.DesiredConnection(); got != (domain.DesiredConnection{ActiveProfileID: "a", WantConnected: true}) {
		t.Errorf("desired = %+v", got)
	}

	d.emit(connectedEvent("10.66.0.2"))
	e := h.waitState(domain.StateConnected)
	if e.VPNIP != "10.66.0.2" || e.Remote != "198.51.100.7:1194" {
		t.Errorf("connected event = %+v", e)
	}
	s := h.m.Status()
	want := Status{
		State: domain.StateConnected, ProfileID: "a", ProfileName: "Profile A", Protocol: fakeProtocol,
		VPNIP: "10.66.0.2", Remote: "198.51.100.7:1194", Since: defaultStart,
	}
	if s != want {
		t.Errorf("Status = %+v, want %+v", s, want)
	}
	if calls := h.guard.recorded(); !slices.Equal(calls, []string{"install", "route 10.66.0.2"}) {
		t.Errorf("netguard calls = %v", calls)
	}
	if h.guard.uiPort != testUIPort || len(h.guard.firewall.Rules) != 1 {
		t.Errorf("firewall got rules %v and UI port %d", h.guard.firewall.Rules, h.guard.uiPort)
	}

	if err := h.m.Disconnect(ctx); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	h.waitState(domain.StateDisconnecting)
	h.waitState(domain.StateDisconnected)
	if calls := h.guard.recorded(); calls[len(calls)-1] != "clear" {
		t.Errorf("routing not cleared on disconnect: %v", calls)
	}
	if got := h.store.DesiredConnection(); got != (domain.DesiredConnection{ActiveProfileID: "a"}) {
		t.Errorf("desired after disconnect = %+v", got)
	}
	if s := h.m.Status(); s.VPNIP != "" || s.State != domain.StateDisconnected {
		t.Errorf("Status after disconnect = %+v", s)
	}
}

// TestManagerRoutesRemoteNetworks: a driver that names remote networks gets
// them routed on every connected event and cleared on disconnect.
func TestManagerRoutesRemoteNetworks(t *testing.T) {
	h := newManagerHarness(t)
	asked := make(chan string, 4)
	networks := []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24"), netip.MustParsePrefix("172.30.0.0/16")}
	h.wrap = func(d *scriptedDriver) Driver {
		return networkedDriver{scriptedDriver: d, networks: networks, asked: asked}
	}
	d := h.connectUp("a", "10.66.0.2")
	d.emit(domain.StateEvent{State: domain.StateReconnecting, Message: "ping-restart"})
	h.waitState(domain.StateReconnecting)
	d.emit(connectedEvent("10.66.0.3"))
	h.waitState(domain.StateConnected)
	if err := h.m.Disconnect(ctx); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	h.waitState(domain.StateDisconnected)

	want := []string{
		"install", "route 10.66.0.2 to [10.99.0.0/24 172.30.0.0/16]", "route 10.66.0.3 to [10.99.0.0/24 172.30.0.0/16]", "clear",
	}
	if calls := h.guard.recorded(); !slices.Equal(calls, want) {
		t.Errorf("netguard calls = %v, want %v", calls, want)
	}
	close(asked)
	var profiles []string
	for id := range asked {
		profiles = append(profiles, id)
	}
	if !slices.Equal(profiles, []string{"a"}) {
		t.Errorf("remote networks asked for %v, want once for profile a", profiles)
	}
}

func TestManagerFirewallFailureRefusesConnect(t *testing.T) {
	h := newManagerHarness(t)
	h.guard.set(func(g *fakeGuard) { g.installErr = errors.New("iptables: permission denied") })
	h.connect("a")
	e := h.waitState(domain.StateError)
	if e.Code != domain.ErrorCodeFirewallFailed || !strings.Contains(e.Message, "permission denied") {
		t.Errorf("error event = %+v", e)
	}
	h.assertNoDriver()
	if s := h.m.Status(); s.LastError == nil || s.LastError.Code != domain.ErrorCodeFirewallFailed {
		t.Errorf("LastError = %+v", s.LastError)
	}
	if pending := h.pending(); !slices.Equal(pending, []time.Duration{2 * time.Second}) {
		t.Fatalf("pending = %v, want a 2s retry", pending)
	}
	h.guard.set(func(g *fakeGuard) { g.installErr = nil })
	h.advance(2 * time.Second)
	h.nextDriver()
	h.waitState(domain.StateConnecting)
}

func TestManagerRoutesOnEveryConnectedEvent(t *testing.T) {
	h := newManagerHarness(t)
	d := h.connectUp("a", "10.66.0.2")
	d.emit(domain.StateEvent{State: domain.StateReconnecting, Message: "ping-restart"})
	if e := h.waitState(domain.StateReconnecting); e.Message != "ping-restart" || e.VPNIP != "10.66.0.2" {
		t.Errorf("reconnecting event = %+v", e)
	}
	d.emit(connectedEvent("10.66.0.9"))
	h.waitState(domain.StateConnected)
	if calls := h.guard.recorded(); !slices.Equal(calls, []string{"install", "route 10.66.0.2", "route 10.66.0.9"}) {
		t.Errorf("netguard calls = %v", calls)
	}
	if s := h.m.Status(); s.VPNIP != "10.66.0.9" {
		t.Errorf("VPN IP = %s", s.VPNIP)
	}
}

// failingRuleAdd is how a failing ip command reaches the manager: the
// command line, its exit status and its standard error (netguard's
// CommandError).
const failingRuleAdd = `route through tunnel: ip rule add fwmark 0x7194/0xffff lookup 7194 priority 7191: exit status 2: ` +
	`RTNETLINK answers: Operation not permitted`

func TestManagerRoutingFailureKeepsTheTunnelUp(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		setup   func(h *managerHarness)
		message string
	}{
		{name: "netguard fails", ip: "10.66.0.2", message: failingRuleAdd, setup: func(h *managerHarness) {
			h.guard.set(func(g *fakeGuard) { g.routeErr = errors.New(failingRuleAdd) })
		}},
		{name: "no VPN IP", ip: "", message: `the driver reported no valid VPN IP ("")`, setup: func(*managerHarness) {}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newManagerHarness(t)
			tt.setup(h)
			h.connect("a")
			d := h.nextDriver()
			d.emit(connectedEvent(tt.ip))
			h.waitLog("applying the tunnel routing failed: " + tt.message + "; the tunnel stays up, retrying the routing in 2s")
			if e := h.waitState(domain.StateConnected); e.VPNIP != tt.ip {
				t.Errorf("connected event = %+v", e)
			}
			s := h.m.Status()
			if w := s.RoutingWarning; s.State != domain.StateConnected || s.LastError != nil || w == nil ||
				w.Code != domain.ErrorCodeRoutingFailed || !strings.Contains(w.Message, tt.message) || !w.Time.Equal(defaultStart) {
				t.Errorf("status = %+v, routing warning %+v", s, s.RoutingWarning)
			}
			if pending := h.pending(); !slices.Equal(pending, []time.Duration{2 * time.Second}) {
				t.Errorf("pending = %v, want the routing retry", pending)
			}
			select {
			case <-d.stopped:
				t.Error("a routing failure stopped the tunnel")
			default:
			}
		})
	}
}

func TestManagerRetriesTheRoutingWithBackoff(t *testing.T) {
	h := newManagerHarness(t)
	h.guard.set(func(g *fakeGuard) { g.routeErr = errors.New(failingRuleAdd) })
	d := h.connectUp("a", "10.66.0.2")
	since := h.m.Status().Since
	for _, delay := range []time.Duration{2 * time.Second, 4 * time.Second} {
		if pending := h.pending(); !slices.Equal(pending, []time.Duration{delay}) {
			t.Fatalf("pending = %v, want %v", pending, delay)
		}
		h.advance(delay)
	}
	h.waitLog("retrying the routing in 8s")

	h.guard.set(func(g *fakeGuard) { g.routeErr = nil })
	h.advance(8 * time.Second)
	h.waitLog("the tunnel routing is applied")
	if e := h.waitState(domain.StateConnected); !e.Since.Equal(since) {
		t.Errorf("the announcement changed the state's time: %+v, want %v", e, since)
	}
	if s := h.m.Status(); s.RoutingWarning != nil || s.State != domain.StateConnected || !s.Since.Equal(since) {
		t.Errorf("status after the routing applied = %+v", s)
	}
	if pending := h.pending(); len(pending) != 0 {
		t.Errorf("pending = %v, want no retry", pending)
	}
	want := []string{"install", "route 10.66.0.2", "route 10.66.0.2", "route 10.66.0.2", "route 10.66.0.2"}
	if calls := h.guard.recorded(); !slices.Equal(calls, want) {
		t.Errorf("netguard calls = %v, want %v", calls, want)
	}

	// A new connected event starts the backoff afresh.
	h.guard.set(func(g *fakeGuard) { g.routeErr = errors.New(failingRuleAdd) })
	d.emit(connectedEvent("10.66.0.9"))
	h.waitLog("retrying the routing in 2s")
	if pending := h.pending(); !slices.Equal(pending, []time.Duration{2 * time.Second}) {
		t.Errorf("pending = %v, want the first retry delay", pending)
	}
}

func TestManagerRoutingRetryWaitsForTheConnectedTunnel(t *testing.T) {
	h := newManagerHarness(t)
	h.guard.set(func(g *fakeGuard) { g.routeErr = errors.New(failingRuleAdd) })
	d := h.connectUp("a", "10.66.0.2")
	d.emit(domain.StateEvent{State: domain.StateReconnecting, Message: "ping-restart"})
	h.waitState(domain.StateReconnecting)
	h.advance(2 * time.Second)
	if calls := h.guard.recorded(); !slices.Equal(calls, []string{"install", "route 10.66.0.2"}) {
		t.Errorf("netguard calls while reconnecting = %v, want no retry", calls)
	}
	if pending := h.pending(); len(pending) != 0 {
		t.Errorf("pending = %v, want the retry dropped", pending)
	}

	d.emit(connectedEvent("10.66.0.2"))
	h.waitState(domain.StateConnected)
	if err := h.m.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.waitState(domain.StateDisconnected)
	if s := h.m.Status(); s.RoutingWarning != nil {
		t.Errorf("routing warning after disconnect = %+v", s.RoutingWarning)
	}
	if pending := h.pending(); len(pending) != 0 {
		t.Errorf("pending = %v, want the routing retry cancelled with the tunnel", pending)
	}
}

func TestManagerRecordsTheNegotiatedChannel(t *testing.T) {
	h := newManagerHarness(t)
	h.connect("a")
	d := h.nextDriver()
	d.emit(domain.ChannelEvent{ControlChannel: "TLSv1.3 TLS_CHACHA20_POLY1305_SHA256"},
		domain.ChannelEvent{DataCipher: "CHACHA20-POLY1305"},
		connectedEvent("10.66.0.2"))
	e := h.events.next(t, "channel event", func(e domain.Event) bool { _, ok := e.(domain.ChannelEvent); return ok })
	if e.Kind() != domain.EventKindChannel {
		t.Errorf("kind = %s", e.Kind())
	}
	h.waitState(domain.StateConnected)
	if s := h.m.Status(); s.DataCipher != "CHACHA20-POLY1305" || s.ControlChannel != "TLSv1.3 TLS_CHACHA20_POLY1305_SHA256" {
		t.Errorf("status = %+v", s)
	}

	// Reconnecting keeps them; a renegotiation updates one of them.
	d.emit(domain.ChannelEvent{DataCipher: "none"}, domain.StateEvent{State: domain.StateReconnecting})
	h.waitState(domain.StateReconnecting)
	if s := h.m.Status(); s.DataCipher != "none" || s.ControlChannel == "" {
		t.Errorf("status while reconnecting = %+v", s)
	}

	if err := h.m.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.waitState(domain.StateDisconnected)
	if s := h.m.Status(); s.DataCipher != "" || s.ControlChannel != "" {
		t.Errorf("status after disconnect = %+v", s)
	}
}

func TestManagerBackoffProgressionAndCap(t *testing.T) {
	h := newManagerHarness(t)
	h.connect("a")
	wantDelays := []time.Duration{2, 4, 8, 16, 32, 60, 60}
	for i, seconds := range wantDelays {
		d := h.nextDriver()
		d.emit(errorEvent(domain.ErrorCodeProcessFailed, "openvpn exited unexpectedly"))
		h.waitState(domain.StateError)
		want := seconds * time.Second
		if pending := h.pending(); !slices.Equal(pending, []time.Duration{want}) {
			t.Fatalf("attempt %d: pending = %v, want %v", i+1, pending, want)
		}
		h.waitLog("retrying in " + want.String())
		h.advance(want)
		h.waitState(domain.StateConnecting)
	}
	d := h.nextDriver()
	d.emit(connectedEvent("10.66.0.2"))
	h.waitState(domain.StateConnected)
	d.emit(errorEvent(domain.ErrorCodeProcessFailed, "crash"))
	h.waitState(domain.StateError)
	if pending := h.pending(); !slices.Equal(pending, []time.Duration{2 * time.Second}) {
		t.Errorf("after a successful connect the backoff restarts at 2s, pending = %v", pending)
	}
}

func TestManagerStopsRetryingOnRejection(t *testing.T) {
	tests := []struct {
		name  string
		event domain.StateEvent
	}{
		{name: "credentials", event: errorEvent(domain.ErrorCodeAuthFailed, "the server rejected the username or password")},
		{name: "server", event: errorEvent(domain.ErrorCodeServerRejected, "the server refused the connection: no shared cipher")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newManagerHarness(t)
			h.connect("a")
			h.nextDriver().emit(tt.event)
			if e := h.waitState(domain.StateError); e.Code != tt.event.Code || e.Message != tt.event.Message {
				t.Errorf("error event = %+v", e)
			}
			if pending := h.pending(); len(pending) != 0 {
				t.Fatalf("a retry is scheduled after a rejection: %v", pending)
			}
			h.advance(time.Hour)
			h.assertNoDriver()

			h.m.ProfileChanged("a")
			h.nextDriver().emit(tt.event)
			h.waitState(domain.StateError)
			h.assertNoDriver()

			h.connect("a")
			h.nextDriver()
			h.waitState(domain.StateConnecting)
			if s := h.m.Status(); s.LastError != nil {
				t.Errorf("a new connect keeps LastError %+v", s.LastError)
			}
		})
	}
}

func TestManagerDriverStartFailures(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantCode  domain.ErrorCode
		wantRetry bool
	}{
		{name: "invalid profile", err: domain.NewValidationError("remoteHost", "is required"), wantCode: domain.ErrorCodeProfileInvalid},
		{name: "spawn failure", err: errors.New("exec: openvpn: not found"), wantCode: domain.ErrorCodeStartFailed, wantRetry: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newManagerHarness(t)
			h.prepare = func(d *scriptedDriver) { d.startErr = tt.err }
			h.connect("a")
			h.nextDriver().awaitStop(t)
			if e := h.waitState(domain.StateError); e.Code != tt.wantCode {
				t.Errorf("error event = %+v, want %s", e, tt.wantCode)
			}
			if retry := len(h.pending()) == 1; retry != tt.wantRetry {
				t.Errorf("retry scheduled = %v, want %v", retry, tt.wantRetry)
			}
		})
	}
}

func TestManagerUnknownProtocolIsNotRetried(t *testing.T) {
	h := newManagerHarness(t)
	h.store.update(func(s *fakeStore) {
		p := s.profiles["a"]
		p.Protocol = "wireguard"
		s.profiles["a"] = p
	})
	h.connect("a")
	if e := h.waitState(domain.StateError); e.Code != domain.ErrorCodeProfileInvalid {
		t.Errorf("error event = %+v", e)
	}
	if pending := h.pending(); len(pending) != 0 {
		t.Errorf("pending = %v", pending)
	}
}

func TestManagerUnexpectedDriverEndIsRetried(t *testing.T) {
	tests := []struct {
		name        string
		end         func(d *scriptedDriver)
		wantMessage string
	}{
		{
			name: "clean exit nobody asked for",
			end: func(d *scriptedDriver) {
				d.emit(domain.StateEvent{State: domain.StateDisconnected, Message: "openvpn exited"})
			},
			wantMessage: "the tunnel ended unexpectedly: openvpn exited",
		},
		{
			name:        "events closed",
			end:         (*scriptedDriver).closeEvents,
			wantMessage: "the driver stopped without reporting why",
		},
		{
			name:        "error without code",
			end:         func(d *scriptedDriver) { d.emit(domain.StateEvent{State: domain.StateError}) },
			wantMessage: "the tunnel ended unexpectedly",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newManagerHarness(t)
			d := h.connectUp("a", "10.66.0.2")
			tt.end(d)
			d.awaitStop(t)
			e := h.waitState(domain.StateError)
			if e.Code != domain.ErrorCodeProcessFailed || e.Message != tt.wantMessage {
				t.Errorf("error event = %+v", e)
			}
			h.advance(2 * time.Second)
			h.nextDriver()
		})
	}
}

func TestManagerDoubleConnectIsANoOp(t *testing.T) {
	h := newManagerHarness(t)
	h.connect("a")
	h.connect("a")
	d := h.nextDriver()
	h.assertNoDriver()
	d.emit(connectedEvent("10.66.0.2"))
	h.waitState(domain.StateConnected)
	h.connect("a")
	h.assertNoDriver()
	if calls := h.guard.recorded(); countOf(calls, "install") != 1 {
		t.Errorf("firewall installed more than once: %v", calls)
	}
}

func TestManagerSwitchProfile(t *testing.T) {
	h := newManagerHarness(t)
	first := h.connectUp("a", "10.66.0.2")
	h.connect("b")
	first.awaitStop(t)
	h.waitState(domain.StateDisconnecting)
	second := h.nextDriver()
	h.waitState(domain.StateConnecting)
	if p, _ := second.started(); p.ID != "b" {
		t.Errorf("second driver started profile %s", p.ID)
	}
	second.emit(connectedEvent("10.77.0.3"))
	h.waitState(domain.StateConnected)
	want := []string{"install", "route 10.66.0.2", "clear", "install", "route 10.77.0.3"}
	if calls := h.guard.recorded(); !slices.Equal(calls, want) {
		t.Errorf("netguard calls = %v, want %v", calls, want)
	}
	if got := h.store.DesiredConnection(); got.ActiveProfileID != "b" || !got.WantConnected {
		t.Errorf("desired = %+v", got)
	}
	if s := h.m.Status(); s.ProfileID != "b" || s.ProfileName != "Profile B" {
		t.Errorf("Status = %+v", s)
	}
}

func TestManagerSlowStopKeepsTheManagerResponsive(t *testing.T) {
	h := newManagerHarness(t)
	gate := h.gate()
	h.prepare = func(d *scriptedDriver) { d.stopGate = gate }
	first := h.connectUp("a", "10.66.0.2")
	if err := h.m.Disconnect(ctx); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	first.awaitStop(t)
	if s := h.m.Status(); s.State != domain.StateDisconnecting {
		t.Errorf("state during the stop = %s", s.State)
	}
	h.prepare = nil
	h.connect("b")
	h.assertNoDriver()
	close(gate)
	second := h.nextDriver()
	h.waitState(domain.StateConnecting)
	if p, _ := second.started(); p.ID != "b" {
		t.Errorf("after the stop the driver started profile %s", p.ID)
	}
}

func TestManagerDisconnectDuringBackoff(t *testing.T) {
	h := newManagerHarness(t)
	h.connect("a")
	h.nextDriver().emit(errorEvent(domain.ErrorCodeProcessFailed, "crash"))
	h.waitState(domain.StateError)
	if err := h.m.Disconnect(ctx); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	h.waitState(domain.StateDisconnected)
	if pending := h.pending(); len(pending) != 0 {
		t.Errorf("pending after disconnect = %v", pending)
	}
	h.advance(time.Minute)
	h.assertNoDriver()
	if s := h.m.Status(); s.LastError != nil {
		t.Errorf("LastError after disconnect = %+v", s.LastError)
	}
}

func TestManagerShutdownDuringConnect(t *testing.T) {
	h := newManagerHarness(t)
	h.connect("a")
	d := h.nextDriver()
	h.waitState(domain.StateConnecting)
	if err := h.m.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	d.awaitStop(t)
	h.events.waitClosed(t)
	if calls := h.guard.recorded(); calls[len(calls)-1] != "clear" {
		t.Errorf("routing not cleared on shutdown: %v", calls)
	}
	if got := h.store.DesiredConnection(); got != (domain.DesiredConnection{ActiveProfileID: "a", WantConnected: true}) {
		t.Errorf("Shutdown changed the desired state: %+v", got)
	}
	if s := h.m.Status(); s.State != domain.StateDisconnected {
		t.Errorf("Status after shutdown = %+v", s)
	}
	if err := h.m.Connect(ctx, "a"); !errors.Is(err, ErrClosed) {
		t.Errorf("Connect after shutdown = %v, want ErrClosed", err)
	}
	events, cancelSubscription := h.m.Subscribe()
	cancelSubscription()
	if _, open := <-events; open {
		t.Error("Subscribe after shutdown returned an open channel")
	}
	if logs := h.m.Logs(0); logs != nil {
		t.Errorf("Logs after shutdown = %v", logs)
	}
	if err := h.m.Shutdown(ctx); err != nil {
		t.Errorf("second Shutdown: %v", err)
	}
}

func TestManagerShutdownWaitsForTheStop(t *testing.T) {
	h := newManagerHarness(t)
	gate := h.gate()
	h.prepare = func(d *scriptedDriver) { d.stopGate = gate }
	h.connectUp("a", "10.66.0.2")
	short, cancel := context.WithCancel(ctx)
	cancel()
	if err := h.m.Shutdown(short); !errors.Is(err, context.Canceled) {
		t.Errorf("Shutdown with an ended context = %v", err)
	}
	if err := h.m.Disconnect(ctx); !errors.Is(err, ErrClosed) {
		t.Errorf("Disconnect while shutting down = %v, want ErrClosed", err)
	}
	close(gate)
	h.events.waitClosed(t)
}

func TestManagerReconnect(t *testing.T) {
	h := newManagerHarness(t)
	if err := h.m.Reconnect(ctx); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("Reconnect without a wanted connection = %v", err)
	}
	first := h.connectUp("a", "10.66.0.2")
	if err := h.m.Reconnect(ctx); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	if e := h.waitState(domain.StateReconnecting); e.Message != reasonReconnect {
		t.Errorf("reconnecting event = %+v", e)
	}
	first.awaitStop(t)
	second := h.nextDriver()
	second.emit(errorEvent(domain.ErrorCodeAuthFailed, "rejected"))
	h.waitState(domain.StateError)
	if err := h.m.Reconnect(ctx); err != nil {
		t.Fatalf("Reconnect after a rejection: %v", err)
	}
	h.nextDriver()
	h.waitState(domain.StateConnecting)
}

func TestManagerRestoresDesiredStateOnStart(t *testing.T) {
	h := newManagerHarness(t)
	h.store.update(func(s *fakeStore) { s.desired = domain.DesiredConnection{ActiveProfileID: "a", WantConnected: true} })
	if err := h.m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	d := h.nextDriver()
	if p, _ := d.started(); p.ID != "a" {
		t.Errorf("restored profile %s", p.ID)
	}
	if calls := h.guard.recorded(); !slices.Equal(calls, []string{"clear", "install"}) {
		t.Errorf("netguard calls = %v, want leftover routing cleared first", calls)
	}
	if err := h.m.Start(ctx); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	h.assertNoDriver()
}

func TestManagerStartWithoutWantedConnection(t *testing.T) {
	h := newManagerHarness(t)
	h.store.update(func(s *fakeStore) { s.desired = domain.DesiredConnection{ActiveProfileID: "a"} })
	if err := h.m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	h.assertNoDriver()
}

func TestManagerDesiredProfileDeleted(t *testing.T) {
	t.Run("before restart", func(t *testing.T) {
		h := newManagerHarness(t)
		h.store.update(func(s *fakeStore) {
			s.desired = domain.DesiredConnection{ActiveProfileID: "gone", WantConnected: true}
		})
		if err := h.m.Start(ctx); err != nil {
			t.Fatalf("Start: %v", err)
		}
		h.waitLog("the profile was deleted")
		h.assertNoDriver()
		if got := h.store.DesiredConnection(); got != (domain.DesiredConnection{}) {
			t.Errorf("desired = %+v, want cleared", got)
		}
	})
	t.Run("while connected", func(t *testing.T) {
		h := newManagerHarness(t)
		d := h.connectUp("a", "10.66.0.2")
		h.store.update(func(s *fakeStore) { delete(s.profiles, "a") })
		h.m.ProfileChanged("a")
		d.awaitStop(t)
		h.waitState(domain.StateDisconnected)
		if got := h.store.DesiredConnection(); got != (domain.DesiredConnection{}) {
			t.Errorf("desired = %+v, want cleared", got)
		}
		if s := h.m.Status(); s.ProfileID != "" || s.State != domain.StateDisconnected {
			t.Errorf("Status = %+v", s)
		}
	})
	t.Run("after disconnect", func(t *testing.T) {
		h := newManagerHarness(t)
		h.connectUp("a", "10.66.0.2")
		if err := h.m.Disconnect(ctx); err != nil {
			t.Fatalf("Disconnect: %v", err)
		}
		h.waitState(domain.StateDisconnected)
		h.store.update(func(s *fakeStore) { delete(s.profiles, "a") })
		h.m.ProfileChanged("a")
		if s := h.m.Status(); s.ProfileID != "" {
			t.Errorf("Status still names the deleted profile: %+v", s)
		}
	})
}

func TestManagerProfileChangedRenamesAndRetries(t *testing.T) {
	h := newManagerHarness(t)
	h.connect("a")
	h.nextDriver().emit(errorEvent(domain.ErrorCodeProcessFailed, "crash"))
	h.waitState(domain.StateError)
	h.store.update(func(s *fakeStore) {
		p := s.profiles["a"]
		p.Name = "Office"
		s.profiles["a"] = p
	})
	h.m.ProfileChanged("b") // not the wanted profile: nothing happens
	h.assertNoDriver()
	h.m.ProfileChanged("a")
	h.nextDriver()
	if s := h.m.Status(); s.ProfileName != "Office" {
		t.Errorf("ProfileName = %q", s.ProfileName)
	}
}

func TestManagerConnectErrors(t *testing.T) {
	h := newManagerHarness(t)
	if err := h.m.Connect(ctx, "missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("Connect(missing) = %v, want ErrNotFound", err)
	}
	persist := errors.New("disk full")
	h.store.update(func(s *fakeStore) { s.desiredErr = persist })
	if err := h.m.Connect(ctx, "a"); !errors.Is(err, persist) {
		t.Errorf("Connect with a failing store = %v", err)
	}
	h.assertNoDriver()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := h.m.Connect(cancelled, "a"); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, persist) {
		t.Errorf("Connect with an ended context = %v", err)
	}
}

func TestManagerDisconnectPersistFailureStillDisconnects(t *testing.T) {
	h := newManagerHarness(t)
	d := h.connectUp("a", "10.66.0.2")
	persist := errors.New("disk full")
	h.store.update(func(s *fakeStore) { s.desiredErr = persist })
	if err := h.m.Disconnect(ctx); !errors.Is(err, persist) {
		t.Errorf("Disconnect = %v, want the persist error", err)
	}
	d.awaitStop(t)
	h.waitState(domain.StateDisconnected)
}

func TestManagerReportsCleanupProblems(t *testing.T) {
	h := newManagerHarness(t)
	h.guard.set(func(g *fakeGuard) { g.clearErr = errors.New("ip: busy") })
	d := h.connectUp("a", "10.66.0.2")
	h.m.ProfileChanged("unknown")
	if err := h.m.Disconnect(ctx); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	d.awaitStop(t)
	h.waitLog("clearing the tunnel routing failed: ip: busy")
}

func TestManagerTrafficRates(t *testing.T) {
	h := newManagerHarness(t)
	d := h.connectUp("a", "10.66.0.2")
	d.emit(domain.TrafficEvent{BytesIn: 1000, BytesOut: 500})
	first := h.waitTraffic()
	if first != (domain.TrafficEvent{BytesIn: 1000, BytesOut: 500}) {
		t.Errorf("first traffic event = %+v, want no rates yet", first)
	}
	h.advance(2 * time.Second)
	d.emit(domain.TrafficEvent{BytesIn: 5000, BytesOut: 2500})
	second := h.waitTraffic()
	if second != (domain.TrafficEvent{BytesIn: 5000, BytesOut: 2500, RateIn: 2000, RateOut: 1000}) {
		t.Errorf("second traffic event = %+v", second)
	}
	d.emit(domain.TrafficEvent{BytesIn: 10, BytesOut: 10})
	if third := h.waitTraffic(); third.RateIn != 2000 {
		t.Errorf("events at the same instant keep the rate: %+v", third)
	}
	h.advance(time.Second)
	d.emit(domain.TrafficEvent{BytesIn: 5, BytesOut: 20})
	if fourth := h.waitTraffic(); fourth.RateIn != 0 || fourth.RateOut != 10 {
		t.Errorf("counters going backwards give rate 0: %+v", fourth)
	}
	if s := h.m.Status(); s.BytesIn != 5 || s.BytesOut != 20 {
		t.Errorf("Status bytes = %d/%d", s.BytesIn, s.BytesOut)
	}

	if err := h.m.Reconnect(ctx); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	h.nextDriver()
	if s := h.m.Status(); s.BytesIn != 0 || s.RateIn != 0 {
		t.Errorf("a new process starts the counters at 0: %+v", s)
	}
}

func (h *managerHarness) waitTraffic() domain.TrafficEvent {
	h.t.Helper()
	e := h.events.next(h.t, "traffic", func(e domain.Event) bool {
		_, ok := e.(domain.TrafficEvent)
		return ok
	})
	return e.(domain.TrafficEvent)
}

func TestManagerLogs(t *testing.T) {
	h := newManagerHarness(t)
	d := h.connectUp("a", "10.66.0.2")
	for _, text := range []string{"one", "two", "three"} {
		d.emit(domain.LogEvent{Level: domain.LogLevelInfo, Text: text})
	}
	h.waitLog("three")
	var texts []string
	for _, line := range h.m.Logs(2) {
		texts = append(texts, line.Text)
	}
	if !slices.Equal(texts, []string{"two", "three"}) {
		t.Errorf("Logs(2) = %v", texts)
	}
	if all := h.m.Logs(0); len(all) < 3 {
		t.Errorf("Logs(0) returned %d lines", len(all))
	}
}

func TestManagerSubscriberFanOut(t *testing.T) {
	h := newManagerHarness(t)
	stalled, _ := h.m.Subscribe()
	live, cancelLive := h.m.Subscribe()
	liveEvents := record(live)
	d := h.connectUp("a", "10.66.0.2")
	for range subscriberBuffer + 10 {
		d.emit(domain.LogEvent{Level: domain.LogLevelInfo, Text: "line"})
	}
	d.emit(domain.LogEvent{Level: domain.LogLevelInfo, Text: "last line"})
	h.waitLog("last line")
	liveEvents.next(t, "last line", func(e domain.Event) bool {
		l, ok := e.(domain.LogEvent)
		return ok && l.Text == "last line"
	})
	received := 0
	for range stalled {
		received++
	}
	if received != subscriberBuffer {
		t.Errorf("stalled subscriber got %d events before being dropped, want %d", received, subscriberBuffer)
	}
	cancelLive()
	cancelLive()
	liveEvents.waitClosed(t)
	if s := h.m.Status(); s.State != domain.StateConnected {
		t.Errorf("manager state = %s", s.State)
	}
}

func countOf(values []string, want string) int {
	n := 0
	for _, v := range values {
		if v == want {
			n++
		}
	}
	return n
}
