package wireguard

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

func TestDriverIdentity(t *testing.T) {
	d := New(Options{})
	if d.Protocol() != domain.ProtocolWireGuard {
		t.Errorf("protocol = %s", d.Protocol())
	}
	if len(d.Describe().Sections) != 2 || d.Advise(domain.PublicProfile{}) != nil {
		t.Error("Describe or Advise differ from the package functions")
	}
	privateKey, publicKey, err := d.GenerateKeyPair()
	if derived, _ := PublicKeyOf(privateKey); err != nil || derived != publicKey {
		t.Errorf("GenerateKeyPair = %v", err)
	}
	var _ vpn.RemoteNetworker = d
}

func TestDriverStartConfiguresTheDevice(t *testing.T) {
	h := newDriverHarness(t)
	// The prefix length of the address adds no route: the device gets /32.
	h.mustStartProfile(validProfile(t, func(s domain.Settings, _ map[string]string) { s.SetString(KeyAddress, "10.66.0.2/24") }))

	device := h.device.snapshot()
	if device.name != testDevice || device.mtu != 1420 {
		t.Errorf("device opened as %s with MTU %d", device.name, device.mtu)
	}
	wantCommands := []string{
		"ip address add 10.66.0.2/32 dev tdvpn0",
		"ip link set dev tdvpn0 mtu 1420 up",
	}
	if !slices.Equal(h.runner.commands, wantCommands) {
		t.Errorf("commands = %q, want %q", h.runner.commands, wantCommands)
	}
	if len(device.sets) != 1 || !strings.HasPrefix(device.sets[0], "private_key="+rfcPrivateHex+"\nreplace_peers=true\n") ||
		!strings.Contains(device.sets[0], "endpoint=198.51.100.23:51820\n") {
		t.Errorf("UAPI set = %q", device.sets)
	}
	if device.keepalives != 1 {
		t.Errorf("keepalives = %d, want 1 to start the handshake", device.keepalives)
	}
	for _, e := range h.taken() {
		if l, ok := e.(domain.LogEvent); ok && (strings.Contains(l.Text, testPrivateKey(t)) || strings.Contains(l.Text, rfcPrivateHex)) {
			t.Errorf("log line shows the private key: %q", l.Text)
		}
	}
}

func TestDriverStartRejectsAnInvalidProfile(t *testing.T) {
	h := newDriverHarness(t)
	p := validProfile(t, func(s domain.Settings, _ map[string]string) { delete(s, KeyAddress) })
	if err := h.start(p); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("Start = %v, want a validation error", err)
	}
	h.assertEventsClosed()
	if h.opener.opened != 0 || h.resolver.lookups != 0 {
		t.Errorf("opened %d devices and resolved %d times, want nothing", h.opener.opened, h.resolver.lookups)
	}
}

// TestDriverSetupFailures: everything after the profile check runs in the
// background, so its failures arrive as an error state.
func TestDriverSetupFailures(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(h *driverHarness)
		code    domain.ErrorCode
		opened  bool
		closed  bool
	}{
		{
			name:    "endpoint does not resolve",
			prepare: func(h *driverHarness) { h.resolver.err = errors.New("no such host") },
			code:    domain.ErrorCodeStartFailed,
		},
		{
			name: "endpoint resolves into a remote network",
			prepare: func(h *driverHarness) {
				h.resolver.answers["vpn.example.com"] = []netip.Addr{netip.MustParseAddr("10.20.1.1")}
			},
			code: domain.ErrorCodeEndpointInTunnel,
		},
		{
			name:    "device cannot be created",
			prepare: func(h *driverHarness) { h.opener.err = errors.New("no /dev/net/tun") },
			code:    domain.ErrorCodeStartFailed, opened: true,
		},
		{
			name:    "address cannot be set",
			prepare: func(h *driverHarness) { h.runner.failOn = "address add" },
			code:    domain.ErrorCodeStartFailed, opened: true, closed: true,
		},
		{
			name:    "configuration refused",
			prepare: func(h *driverHarness) { h.device.setErr = errors.New("UAPI error 22") },
			code:    domain.ErrorCodeStartFailed, opened: true, closed: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newDriverHarness(t)
			tt.prepare(h)
			if err := h.start(validProfile(t, nil)); err != nil {
				t.Fatalf("Start = %v, want the failure as an event", err)
			}
			if got := h.failedState(); got.Code != tt.code || !strings.HasPrefix(got.Message, "starting the WireGuard tunnel failed: ") {
				t.Errorf("error state = %+v, want code %s", got, tt.code)
			}
			if got := h.opener.opened > 0; got != tt.opened {
				t.Errorf("device opened = %v", got)
			}
			if got := h.device.snapshot().closed; got != tt.closed {
				t.Errorf("device closed = %v", got)
			}
			if len(h.clock.Pending()) != 0 {
				t.Errorf("timers left: %v", h.clock.Pending())
			}
		})
	}
}

// TestDriverStartDoesNotWaitForTheNameServer: Start returns while the
// endpoint is still being resolved, and Stop ends that resolution.
func TestDriverStartDoesNotWaitForTheNameServer(t *testing.T) {
	h := newDriverHarness(t)
	h.resolver.hold, h.resolver.entered = make(chan struct{}), make(chan struct{}, 1)
	if err := h.start(validProfile(t, nil)); err != nil {
		t.Fatal(err)
	}
	<-h.resolver.entered
	h.stopWithin(5 * time.Second)
	h.assertEventsClosed()
	if got := states(h.taken()); len(got) != 1 || got[0].State != domain.StateDisconnected {
		t.Errorf("states = %+v, want disconnected", got)
	}
	if h.opener.opened != 0 {
		t.Error("a device was opened after the stop")
	}
}

func TestDriverStartsOnce(t *testing.T) {
	h := newDriverHarness(t)
	h.mustStart()
	if err := h.start(validProfile(t, nil)); err == nil {
		t.Error("second Start succeeded")
	}
	stopped := New(Options{})
	if err := stopped.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := stopped.Start(context.Background(), validProfile(t, nil), nil); err == nil {
		t.Error("Start after Stop succeeded")
	}
}

func TestDriverConnectsOnTheFirstHandshake(t *testing.T) {
	h := newDriverHarness(t)
	h.mustStart()

	h.device.set(func(f *fakeDevice) { f.stats.txBytes = 148 })
	h.advance(pollInterval)
	events := h.taken()
	if traffic, ok := lastTraffic(events); !ok || traffic.BytesOut != 148 {
		t.Errorf("traffic = %+v, %v", traffic, ok)
	}
	if got := states(events); len(got) != 0 {
		t.Errorf("states while waiting = %+v", got)
	}

	h.advance(noAnswerDelay - pollInterval)
	events = h.taken()
	notes := states(events)
	if len(notes) != 1 || notes[0].State != domain.StateConnecting || notes[0].MessageCode != MessageNoHandshake {
		t.Fatalf("states after 30 s = %+v, want the no-answer note", notes)
	}
	h.advance(10 * pollInterval)
	if got := states(h.taken()); len(got) != 0 {
		t.Errorf("the note was repeated: %+v", got)
	}
	if got := h.device.snapshot().keepalives; got < 20 {
		t.Errorf("keepalives = %d, want one per check while waiting", got)
	}

	at := h.handshake(92, 1480)
	h.advance(pollInterval)
	events = h.taken()
	connected := states(events)
	if len(connected) != 1 || connected[0].State != domain.StateConnected {
		t.Fatalf("states = %+v, want connected", connected)
	}
	if c := connected[0]; c.VPNIP != "10.66.0.2" || c.Remote != "198.51.100.23:51820" || !c.Since.Equal(at) {
		t.Errorf("connected = %+v, want since %v", c, at)
	}
	if !slices.ContainsFunc(events, func(e domain.Event) bool {
		c, ok := e.(domain.ChannelEvent)
		return ok && c.DataCipher == "ChaCha20-Poly1305" && c.ControlChannel == ""
	}) {
		t.Errorf("no channel event in %+v", events)
	}
	if traffic, _ := lastTraffic(events); traffic.BytesIn != 92 || traffic.BytesOut != 1480 {
		t.Errorf("traffic = %+v", traffic)
	}
	keepalives := h.device.snapshot().keepalives
	h.advance(5 * pollInterval)
	if got := h.device.snapshot().keepalives; got != keepalives {
		t.Errorf("keepalives while connected = %d, want %d", got, keepalives)
	}
}

func TestDriverReconnectsWhenHandshakesStop(t *testing.T) {
	h := newDriverHarness(t)
	h.mustStart()
	h.handshake(100, 200)
	h.advance(pollInterval)
	h.taken()

	// Handshakes keep coming: still connected after much longer than 180 s.
	for range 3 {
		h.advance(120 * time.Second)
		h.handshake(500, 600)
	}
	h.advance(pollInterval)
	if got := states(h.taken()); len(got) != 0 {
		t.Fatalf("states while handshakes come = %+v", got)
	}

	// The server goes silent while the device keeps sending.
	h.resolver.answers["vpn.example.com"] = []netip.Addr{netip.MustParseAddr("198.51.100.99")}
	lookups := h.resolver.lookups
	h.sends(900)
	h.advance(handshakeTimeout - 2*pollInterval)
	if got := states(h.taken()); len(got) != 0 {
		t.Fatalf("states before 180 s = %+v", got)
	}
	h.advance(3 * pollInterval)
	events := h.taken()
	got := states(events)
	if len(got) != 1 || got[0].State != domain.StateReconnecting {
		t.Fatalf("states after 180 s = %+v, want reconnecting", got)
	}
	if h.resolver.lookups != lookups+1 {
		t.Errorf("lookups = %d, want the endpoint resolved again", h.resolver.lookups-lookups)
	}
	sets := h.device.snapshot().sets
	if last := sets[len(sets)-1]; last != renderEndpointUpdate(keyFromHex(t, bobPublicHex), netip.MustParseAddrPort("198.51.100.99:51820")) {
		t.Errorf("last UAPI set = %q, want the re-set peer", last)
	}
	if !hasLog(events, "now resolves to 198.51.100.99:51820") {
		t.Errorf("no log line about the new address in %+v", events)
	}

	// No answer for another 180 s: the endpoint is resolved once more.
	h.advance(handshakeTimeout)
	if h.resolver.lookups != lookups+2 {
		t.Errorf("lookups = %d, want a second resolution", h.resolver.lookups-lookups)
	}
	at := h.handshake(1000, 2000)
	h.advance(pollInterval)
	back := states(h.taken())
	if len(back) != 1 || back[0].State != domain.StateConnected || !back[0].Since.Equal(at) || back[0].Remote != "198.51.100.99:51820" {
		t.Errorf("states = %+v, want connected again since %v", back, at)
	}
}

func TestDriverStaysConnectedWhileIdle(t *testing.T) {
	h := newDriverHarness(t)
	h.mustStart()
	h.handshake(100, 200)
	h.advance(pollInterval)
	h.taken()

	// No traffic and no keepalives: no handshakes, nothing sent.
	h.advance(10 * time.Minute)
	if got := states(h.taken()); len(got) != 0 {
		t.Errorf("states of an idle tunnel = %+v", got)
	}
}

func TestDriverWaitsForASecondCheckBeforeReconnecting(t *testing.T) {
	h := newDriverHarness(t)
	h.mustStart()
	h.handshake(100, 200)
	h.advance(pollInterval)
	h.advance(10 * time.Minute)
	h.taken()

	// Traffic starts after a long idle time; the handshake it triggers
	// arrives before the next check.
	h.sends(348)
	h.advance(pollInterval)
	h.handshake(150, 400)
	h.advance(pollInterval)
	if got := states(h.taken()); len(got) != 0 {
		t.Errorf("states = %+v, want none", got)
	}
}

func TestDriverReportsADeviceFailure(t *testing.T) {
	tests := []struct {
		name        string
		breakDevice func(f *fakeDevice)
	}{
		{"device closed", func(f *fakeDevice) { close(f.done) }},
		{"state unreadable", func(f *fakeDevice) { f.getErr = errors.New("closed") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newDriverHarness(t)
			h.mustStart()
			h.device.set(tt.breakDevice)
			h.advance(pollInterval)
			h.assertEventsClosed()
			got := states(h.taken())
			if len(got) != 1 || got[0].State != domain.StateError || got[0].Code != domain.ErrorCodeProcessFailed {
				t.Errorf("states = %+v, want a process failure", got)
			}
			if !h.device.snapshot().closed {
				t.Error("the device was not closed")
			}
			if err := h.driver.Stop(context.Background()); err != nil {
				t.Errorf("Stop after the failure = %v", err)
			}
		})
	}
}

func TestDriverStop(t *testing.T) {
	h := newDriverHarness(t)
	h.mustStart()
	h.handshake(1, 2)
	h.advance(pollInterval)
	h.taken()

	if err := h.driver.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.assertEventsClosed()
	got := states(h.taken())
	if len(got) != 1 || got[0].State != domain.StateDisconnected {
		t.Errorf("states = %+v, want disconnected", got)
	}
	if !h.device.snapshot().closed {
		t.Error("the device was not closed")
	}
	if len(h.clock.Pending()) != 0 {
		t.Errorf("timers left: %v", h.clock.Pending())
	}
	if err := h.driver.Stop(context.Background()); err != nil {
		t.Errorf("second Stop = %v", err)
	}
	// Late device log lines after the stop are dropped, not sent on the
	// closed channel.
	h.device.log.Verbose("Interface state was Up, requested Down, now Down")
}

func TestDriverStopWithoutStart(t *testing.T) {
	d := New(Options{})
	if err := d.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := <-d.Events(); ok {
		t.Error("Events is open")
	}
}

func TestDriverDropsDeviceLinesWhenNobodyReads(t *testing.T) {
	h := newDriverHarness(t)
	h.mustStart()
	h.taken()
	for range 2 * eventBuffer {
		h.device.log.Error("Failed to send handshake initiation: network is unreachable")
	}
	h.drain()
	if n := len(h.taken()); n != eventBuffer {
		t.Errorf("read %d events, want the buffer of %d", n, eventBuffer)
	}
}

// connectAndGoSilent connects h, lets the server stop answering while the
// device keeps sending, and advances to just before the tunnel counts as
// lost; the next three checks find it lost.
func connectAndGoSilent(h *driverHarness) {
	h.mustStart()
	h.handshake(100, 200)
	h.advance(pollInterval)
	h.sends(900)
	h.advance(handshakeTimeout - 2*pollInterval)
	h.taken()
}

func TestDriverFailsWhenTheEndpointMovesIntoARemoteNetwork(t *testing.T) {
	h := newDriverHarness(t)
	connectAndGoSilent(h)
	h.resolver.answers["vpn.example.com"] = []netip.Addr{netip.MustParseAddr("10.20.0.7")}
	h.advance(3 * pollInterval)
	got := h.failedState()
	if got.Code != domain.ErrorCodeEndpointInTunnel || !strings.Contains(got.Message, "10.20.0.0/16") {
		t.Errorf("error state = %+v, want endpoint_in_tunnel naming the network", got)
	}
	if !h.device.snapshot().closed {
		t.Error("the device was not closed")
	}
}

// TestDriverStopDoesNotWaitForTheNameServer: resolving the endpoint again
// runs without the lock, so Stop returns while the name server is silent.
func TestDriverStopDoesNotWaitForTheNameServer(t *testing.T) {
	h := newDriverHarness(t)
	connectAndGoSilent(h)
	h.resolver.hold, h.resolver.entered = make(chan struct{}), make(chan struct{}, 1)
	advanced := make(chan struct{})
	go func() {
		defer close(advanced)
		for range 3 {
			h.clock.Advance(pollInterval)
		}
	}()
	<-h.resolver.entered
	h.stopWithin(5 * time.Second)
	<-advanced
	h.assertEventsClosed()
	got := states(h.taken())
	if len(got) != 2 || got[0].State != domain.StateReconnecting || got[1].State != domain.StateDisconnected {
		t.Errorf("states = %+v, want reconnecting, then disconnected", got)
	}
	if sets := h.device.snapshot().sets; len(sets) != 1 {
		t.Errorf("UAPI sets after the stop: %q", sets[1:])
	}
}

// TestDriverAgesHandshakesByItsOwnClock: the device reports handshake times
// on the wall clock, which NTP may step; their age counts from when the
// driver saw them change.
func TestDriverAgesHandshakesByItsOwnClock(t *testing.T) {
	h := newDriverHarness(t)
	h.mustStart()
	// The wall clock was 10 minutes behind at the handshake.
	h.device.set(func(f *fakeDevice) {
		f.stats = peerStats{lastHandshake: h.clock.Now().Add(-10 * time.Minute), txBytes: 200}
	})
	h.advance(pollInterval)
	if got := states(h.taken()); len(got) != 1 || got[0].State != domain.StateConnected {
		t.Fatalf("states = %+v, want connected", got)
	}
	h.sends(900)
	h.advance(handshakeTimeout - 2*pollInterval)
	if got := states(h.taken()); len(got) != 0 {
		t.Fatalf("states = %+v, want connected for 180 s after the handshake was seen", got)
	}

	// The clock is set back: the next handshake has an earlier time, and
	// still counts as new.
	h.device.set(func(f *fakeDevice) { f.stats.lastHandshake = h.clock.Now().Add(-time.Hour) })
	h.advance(pollInterval)
	h.advance(handshakeTimeout - 2*pollInterval)
	if got := states(h.taken()); len(got) != 0 {
		t.Fatalf("states = %+v, want the earlier handshake taken as new", got)
	}
	h.sends(1800)
	h.advance(4 * pollInterval)
	if got := states(h.taken()); len(got) != 1 || got[0].State != domain.StateReconnecting {
		t.Errorf("states = %+v, want reconnecting 180 s after the last handshake was seen", got)
	}
}
