package wireguard

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"tunneldeck/internal/domain"
)

// Timing of the handshake watch (SPEC §18).
const (
	// pollInterval is the cadence of the traffic events, as OpenVPN's
	// "bytecount 2", and of the handshake checks.
	pollInterval = 2 * time.Second
	// noAnswerDelay is how long the first handshake may take before the
	// status names the likely causes.
	noAnswerDelay = 30 * time.Second
	// handshakeTimeout is how old the last handshake may get before the
	// tunnel counts as lost (WireGuard rejects keys after 180 s), and the
	// interval of resolving the endpoint again while no handshake comes.
	handshakeTimeout = 180 * time.Second
	// staleConfirmations is how many checks in a row must find the tunnel
	// lost, so that a handshake under way at one check does not count.
	staleConfirmations = 2
	// resolveTimeout bounds one name resolution of the endpoint.
	resolveTimeout = 10 * time.Second
)

// DataCipher is WireGuard's fixed data channel cipher.
const DataCipher = "ChaCha20-Poly1305"

// MessageNoHandshake is the status message code while the server has not
// answered the first handshake for noAnswerDelay.
const MessageNoHandshake = "wireguard_no_handshake"

// tunnel watches one running device. Every pollInterval it reads the
// server's handshake and byte counters: connecting until the first
// handshake, connected (since the handshake) while handshakes keep coming,
// reconnecting when the last handshake is handshakeTimeout old although the
// device sent something since. While no handshake comes it keeps asking
// for one and resolves the endpoint again every handshakeTimeout.
type tunnel struct {
	driver *Driver
	device Device
	config profileConfig
	vpnIP  string

	// mu serialises the checks with stop; the fields below are guarded
	// by it.
	mu       sync.Mutex
	stopped  bool
	stopPoll func() bool
	server   netip.AddrPort // the endpoint's current address
	// waitingSince is when the current wait for a handshake began;
	// resolvedAt when the endpoint was last resolved.
	waitingSince time.Time
	resolvedAt   time.Time
	connected    bool
	noAnswerSent bool
	// handshake is the newest handshake seen, zero before the first;
	// txAtHandshake the sent bytes when it was seen.
	handshake     time.Time
	txAtHandshake uint64
	staleChecks   int
}

func newTunnel(d *Driver, device Device, c profileConfig, server netip.AddrPort) *tunnel {
	now := d.opts.Clock.Now()
	return &tunnel{
		driver: d, device: device, config: c, vpnIP: c.address.Addr().String(),
		server: server, waitingSince: now, resolvedAt: now,
	}
}

// begin asks for the first handshake and starts the checks. It runs inside
// Start, so its log line must not wait for a reader.
func (t *tunnel) begin() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.driver.tryLog(domain.LogLevelInfo, "WireGuard device "+t.driver.opts.DeviceName+" is up; waiting for the first handshake with "+t.server.String())
	t.device.SendKeepalive(t.config.peerPublicKey)
	t.schedule()
}

func (t *tunnel) schedule() {
	t.stopPoll = t.driver.opts.Clock.AfterFunc(pollInterval, t.poll)
}

func (t *tunnel) poll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped {
		return
	}
	select {
	case <-t.device.Done():
		t.fail("the WireGuard device stopped unexpectedly")
		return
	default:
	}
	dump, err := t.device.IpcGet()
	if err != nil {
		t.fail("reading the WireGuard device state failed: " + err.Error())
		return
	}
	stats, err := parsePeerStats(dump, t.config.peerPublicKey)
	if err != nil {
		t.fail("reading the WireGuard device state failed: " + err.Error())
		return
	}
	t.driver.emit(domain.TrafficEvent{BytesIn: stats.rxBytes, BytesOut: stats.txBytes})
	now := t.driver.opts.Clock.Now()
	if t.connected {
		t.watchConnected(stats, now)
	} else {
		t.watchWaiting(stats, now)
	}
	t.schedule()
}

// watchWaiting handles a check while no handshake is current: a new one
// connects; otherwise the server is asked again.
func (t *tunnel) watchWaiting(stats peerStats, now time.Time) {
	if stats.lastHandshake.After(t.handshake) {
		t.handshakeCompleted(stats)
		return
	}
	if t.handshake.IsZero() && !t.noAnswerSent && now.Sub(t.waitingSince) >= noAnswerDelay {
		t.noAnswerSent = true
		t.driver.emit(domain.StateEvent{
			State: domain.StateConnecting, Message: "No answer from the server – check the keys and the endpoint",
			MessageCode: MessageNoHandshake, Since: now.UTC(),
		})
		t.driver.log(domain.LogLevelWarn, "no answer from the server after 30 seconds; check the keys and the endpoint")
	}
	if now.Sub(t.resolvedAt) >= handshakeTimeout {
		t.resetPeer(now)
	}
	t.device.SendKeepalive(t.config.peerPublicKey)
}

func (t *tunnel) handshakeCompleted(stats peerStats) {
	t.connected = true
	t.handshake, t.txAtHandshake, t.staleChecks = stats.lastHandshake, stats.txBytes, 0
	t.driver.log(domain.LogLevelInfo, "handshake with the server completed")
	t.driver.emit(domain.StateEvent{
		State: domain.StateConnected, VPNIP: t.vpnIP, Remote: t.server.String(), Since: stats.lastHandshake.UTC(),
	})
	t.driver.emit(domain.ChannelEvent{DataCipher: DataCipher})
}

// watchConnected follows the handshakes of a connected tunnel. The tunnel
// is lost when the last handshake is handshakeTimeout old and the device
// has sent something since: an idle tunnel without keepalives makes no
// handshakes, yet nothing is wrong with it.
func (t *tunnel) watchConnected(stats peerStats, now time.Time) {
	if stats.lastHandshake.After(t.handshake) {
		t.handshake, t.txAtHandshake, t.staleChecks = stats.lastHandshake, stats.txBytes, 0
		return
	}
	if now.Sub(t.handshake) < handshakeTimeout || stats.txBytes <= t.txAtHandshake {
		t.staleChecks = 0
		return
	}
	t.staleChecks++
	if t.staleChecks >= staleConfirmations {
		t.lost(now)
	}
}

// lost reports the tunnel as reconnecting, resolves the endpoint again
// (DynDNS) and re-sets the peer.
func (t *tunnel) lost(now time.Time) {
	t.connected, t.staleChecks, t.waitingSince = false, 0, now
	t.driver.emit(domain.StateEvent{
		State: domain.StateReconnecting, Message: "no handshake with the server for 3 minutes", Since: now.UTC(),
	})
	t.driver.log(domain.LogLevelWarn, "no handshake with the server for 3 minutes; resolving the endpoint again")
	t.resetPeer(now)
	t.device.SendKeepalive(t.config.peerPublicKey)
}

// resetPeer resolves the endpoint again and points the peer at the
// result. A failure keeps the known address; the next try follows after
// handshakeTimeout.
func (t *tunnel) resetPeer(now time.Time) {
	t.resolvedAt = now
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()
	server, err := resolve(ctx, t.driver.opts.Resolver, t.config.endpoint)
	if err != nil {
		t.driver.log(domain.LogLevelWarn, err.Error()+"; keeping "+t.server.String())
		return
	}
	if err := t.device.IpcSet(renderEndpointUpdate(t.config.peerPublicKey, server)); err != nil {
		t.driver.log(domain.LogLevelError, "updating the endpoint failed: "+err.Error())
		return
	}
	if server != t.server {
		t.driver.log(domain.LogLevelInfo, "the endpoint "+t.config.endpoint.String()+" now resolves to "+server.String())
	}
	t.server = server
}

// fail ends a tunnel whose device broke; the manager decides on a retry.
func (t *tunnel) fail(message string) {
	t.stopped = true
	t.device.Close()
	t.driver.log(domain.LogLevelError, message)
	t.driver.emit(domain.StateEvent{
		State: domain.StateError, Code: domain.ErrorCodeProcessFailed, Message: message, Since: t.driver.now(),
	})
	t.driver.finish()
}

// stop removes the device, reports "disconnected" and closes Events.
func (t *tunnel) stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped {
		return
	}
	t.stopped = true
	if t.stopPoll != nil {
		t.stopPoll()
	}
	t.device.Close()
	t.driver.log(domain.LogLevelInfo, "WireGuard device "+t.driver.opts.DeviceName+" removed")
	t.driver.emit(domain.StateEvent{State: domain.StateDisconnected, Since: t.driver.now()})
	t.driver.finish()
}
