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
	h.mustStart()

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

func TestDriverStartFailures(t *testing.T) {
	tests := []struct {
		name       string
		profile    func(t *testing.T) domain.Profile
		prepare    func(h *driverHarness)
		validation bool
		opened     bool
		closed     bool
	}{
		{
			name: "invalid profile",
			profile: func(t *testing.T) domain.Profile {
				return validProfile(t, func(s domain.Settings, _ map[string]string) { delete(s, KeyAddress) })
			},
			validation: true,
		},
		{
			name:    "endpoint does not resolve",
			profile: func(t *testing.T) domain.Profile { return validProfile(t, nil) },
			prepare: func(h *driverHarness) { h.resolver.err = errors.New("no such host") },
		},
		{
			name:    "device cannot be created",
			profile: func(t *testing.T) domain.Profile { return validProfile(t, nil) },
			prepare: func(h *driverHarness) { h.opener.err = errors.New("no /dev/net/tun") },
			opened:  true,
		},
		{
			name:    "address cannot be set",
			profile: func(t *testing.T) domain.Profile { return validProfile(t, nil) },
			prepare: func(h *driverHarness) { h.runner.failOn = "address add" },
			opened:  true, closed: true,
		},
		{
			name:    "configuration refused",
			profile: func(t *testing.T) domain.Profile { return validProfile(t, nil) },
			prepare: func(h *driverHarness) { h.device.setErr = errors.New("UAPI error 22") },
			opened:  true, closed: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newDriverHarness(t)
			if tt.prepare != nil {
				tt.prepare(h)
			}
			err := h.start(tt.profile(t))
			if err == nil {
				t.Fatal("Start succeeded")
			}
			if got := errors.Is(err, domain.ErrValidation); got != tt.validation {
				t.Errorf("validation error = %v: %v", got, err)
			}
			if got := h.opener.opened > 0; got != tt.opened {
				t.Errorf("device opened = %v", got)
			}
			if got := h.device.snapshot().closed; got != tt.closed {
				t.Errorf("device closed = %v", got)
			}
			h.assertEventsClosed()
			if len(h.clock.Pending()) != 0 {
				t.Errorf("timers left: %v", h.clock.Pending())
			}
		})
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
