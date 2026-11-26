package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"tunneldeck/internal/domain"
)

// Timing of the tunnel (SPEC §18).
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
	// resolveTimeout bounds one name resolution of the endpoint while the
	// tunnel runs.
	resolveTimeout = 10 * time.Second
	// setupTimeout bounds bringing the device up: resolving the endpoint,
	// the ip commands and the configuration.
	setupTimeout = 30 * time.Second
)

// DataCipher is WireGuard's fixed data channel cipher.
const DataCipher = "ChaCha20-Poly1305"

// MessageNoHandshake is the status message code while the server has not
// answered the first handshake for noAnswerDelay.
const MessageNoHandshake = "wireguard_no_handshake"

// endpointInTunnelError reports an endpoint address inside one of the
// profile's remote networks: rule 7180 would route the tunnel's own UDP
// packets into the tunnel.
type endpointInTunnelError struct {
	server  netip.AddrPort
	network netip.Prefix
}

func (e endpointInTunnelError) Error() string {
	return fmt.Sprintf("the endpoint %s lies in %s, which the profile routes through the tunnel; its packets would loop into the tunnel",
		e.server, e.network)
}

// tunnel is one WireGuard device from its setup to its removal. run brings
// it up in the background; then, every pollInterval, it reads the server's
// handshake and byte counters: connecting until the first handshake,
// connected (since the handshake) while handshakes keep coming,
// reconnecting when the last handshake is handshakeTimeout old although
// the device sent something since. While no handshake comes it keeps
// asking for one and resolves the endpoint again every handshakeTimeout.
type tunnel struct {
	driver *Driver
	config profileConfig
	vpnIP  string
	// ctx ends with stop; it bounds the setup and every name resolution.
	ctx    context.Context
	cancel context.CancelFunc

	// mu serialises the checks with stop; the fields below are guarded
	// by it. Name resolution runs without it.
	mu       sync.Mutex
	stopped  bool
	device   Device // nil while the setup runs
	stopPoll func() bool
	server   netip.AddrPort // the endpoint's current address
	// waitingSince is when the current wait for a handshake began;
	// resolvedAt when the endpoint was last resolved, zero to resolve it
	// at the end of the current check.
	waitingSince time.Time
	resolvedAt   time.Time
	connected    bool
	noAnswerSent bool
	// handshake is the newest handshake time the device reported, zero
	// before the first. Its age is measured from handshakeSeen, the time on
	// the driver's clock when it was first read, so that a step of the wall
	// clock (NTP) does not age it; txAtHandshake are the sent bytes then.
	handshake     time.Time
	handshakeSeen time.Time
	txAtHandshake uint64
	staleChecks   int
}

func newTunnel(d *Driver, c profileConfig) *tunnel {
	ctx, cancel := context.WithCancel(context.Background())
	return &tunnel{driver: d, config: c, vpnIP: c.address.Addr().String(), ctx: ctx, cancel: cancel}
}

// run brings the device up and starts the checks. It runs in its own
// goroutine; a failure ends the tunnel with an "error" state.
func (t *tunnel) run() {
	device, server, err := t.setUp()
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case t.stopped:
		t.closeDown(device)
	case err != nil:
		t.stopped = true
		t.cancel()
		t.report(failureCode(err), "starting the WireGuard tunnel failed: "+err.Error())
	default:
		t.begin(device, server)
	}
}

// setUp resolves the endpoint, creates the device and configures it.
func (t *tunnel) setUp() (Device, netip.AddrPort, error) {
	ctx, cancel := context.WithTimeout(t.ctx, setupTimeout)
	defer cancel()
	server, err := t.resolveServer(ctx)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	d := t.driver
	device, err := d.opts.Opener.Open(d.opts.DeviceName, t.config.mtu, d.deviceLog())
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	if err := d.configure(ctx, device, t.config, server); err != nil {
		device.Close()
		return nil, netip.AddrPort{}, err
	}
	return device, server, nil
}

// resolveServer resolves the endpoint and refuses an address inside one of
// the remote networks (the allowed IPs other than 0.0.0.0/0).
func (t *tunnel) resolveServer(ctx context.Context) (netip.AddrPort, error) {
	server, err := resolve(ctx, t.driver.opts.Resolver, t.config.endpoint)
	if err != nil {
		return netip.AddrPort{}, err
	}
	for _, network := range t.config.allowedIPs {
		if network != everything && network.Contains(server.Addr()) {
			return netip.AddrPort{}, endpointInTunnelError{server: server, network: network}
		}
	}
	return server, nil
}

func failureCode(err error) domain.ErrorCode {
	var inTunnel endpointInTunnelError
	if errors.As(err, &inTunnel) {
		return domain.ErrorCodeEndpointInTunnel
	}
	return domain.ErrorCodeStartFailed
}

// begin keeps the running device, asks for the first handshake and starts
// the checks. The caller holds mu.
func (t *tunnel) begin(device Device, server netip.AddrPort) {
	now := t.driver.opts.Clock.Now()
	t.device, t.server, t.waitingSince, t.resolvedAt = device, server, now, now
	t.driver.log(domain.LogLevelInfo, "WireGuard device "+t.driver.opts.DeviceName+" is up; waiting for the first handshake with "+server.String())
	device.SendKeepalive(t.config.peerPublicKey)
	t.schedule()
}

// schedule arms the next check; the caller holds mu.
func (t *tunnel) schedule() {
	t.stopPoll = t.driver.opts.Clock.AfterFunc(pollInterval, t.poll)
}

// poll runs one check, resolves the endpoint again when that is due, and
// arms the next check.
func (t *tunnel) poll() {
	reresolve, running := t.check()
	if !running {
		return
	}
	if reresolve {
		t.reresolve()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.stopped {
		t.schedule()
	}
}

// check reads the device, reports the traffic and moves the state. It
// reports whether the endpoint is due to be resolved again, and running =
// false once the tunnel is stopped or failed.
func (t *tunnel) check() (reresolve, running bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped {
		return false, false
	}
	select {
	case <-t.device.Done():
		t.fail(domain.ErrorCodeProcessFailed, "the WireGuard device stopped unexpectedly")
		return false, false
	default:
	}
	stats, err := t.readStats()
	if err != nil {
		t.fail(domain.ErrorCodeProcessFailed, "reading the WireGuard device state failed: "+err.Error())
		return false, false
	}
	t.driver.emit(domain.TrafficEvent{BytesIn: stats.rxBytes, BytesOut: stats.txBytes})
	now := t.driver.opts.Clock.Now()
	if t.connected {
		t.watchConnected(stats, now)
	} else {
		t.watchWaiting(stats, now)
	}
	return !t.connected && now.Sub(t.resolvedAt) >= handshakeTimeout, true
}

func (t *tunnel) readStats() (peerStats, error) {
	dump, err := t.device.IpcGet()
	if err != nil {
		return peerStats{}, err
	}
	return parsePeerStats(dump, t.config.peerPublicKey)
}

// isNewHandshake reports whether the device reports another handshake than
// the one seen last. Any change counts, also to an earlier time after the
// wall clock was set back.
func (t *tunnel) isNewHandshake(stats peerStats) bool {
	return !stats.lastHandshake.IsZero() && !stats.lastHandshake.Equal(t.handshake)
}

func (t *tunnel) recordHandshake(stats peerStats, now time.Time) {
	t.handshake, t.handshakeSeen, t.txAtHandshake, t.staleChecks = stats.lastHandshake, now, stats.txBytes, 0
}

// watchWaiting handles a check while no handshake is current: a new one
// connects; otherwise the server is asked again.
func (t *tunnel) watchWaiting(stats peerStats, now time.Time) {
	if t.isNewHandshake(stats) {
		t.handshakeCompleted(stats, now)
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
	t.device.SendKeepalive(t.config.peerPublicKey)
}

func (t *tunnel) handshakeCompleted(stats peerStats, now time.Time) {
	t.connected = true
	t.recordHandshake(stats, now)
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
	if t.isNewHandshake(stats) {
		t.recordHandshake(stats, now)
		return
	}
	if now.Sub(t.handshakeSeen) < handshakeTimeout || stats.txBytes <= t.txAtHandshake {
		t.staleChecks = 0
		return
	}
	t.staleChecks++
	if t.staleChecks >= staleConfirmations {
		t.lost(now)
	}
}

// lost reports the tunnel as reconnecting and has the endpoint resolved
// again (DynDNS) at the end of this check.
func (t *tunnel) lost(now time.Time) {
	t.connected, t.staleChecks, t.waitingSince, t.resolvedAt = false, 0, now, time.Time{}
	t.driver.emit(domain.StateEvent{
		State: domain.StateReconnecting, Message: "no handshake with the server for 3 minutes", Since: now.UTC(),
	})
	t.driver.log(domain.LogLevelWarn, "no handshake with the server for 3 minutes; resolving the endpoint again")
	t.device.SendKeepalive(t.config.peerPublicKey)
}

// reresolve resolves the endpoint again and re-sets the peer to the
// result. The lock is not held while the name server answers, so Stop
// never waits for it. A failed resolution keeps the known address; an
// address inside a remote network ends the tunnel.
func (t *tunnel) reresolve() {
	ctx, cancel := context.WithTimeout(t.ctx, resolveTimeout)
	defer cancel()
	server, err := t.resolveServer(ctx)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped {
		return
	}
	t.resolvedAt = t.driver.opts.Clock.Now()
	var inTunnel endpointInTunnelError
	switch {
	case errors.As(err, &inTunnel):
		t.fail(domain.ErrorCodeEndpointInTunnel, err.Error())
		return
	case err != nil:
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
	t.device.SendKeepalive(t.config.peerPublicKey)
}

// fail ends a running tunnel whose device broke or whose endpoint became
// unusable; the manager decides on a retry. The caller holds mu.
func (t *tunnel) fail(code domain.ErrorCode, message string) {
	t.stopped = true
	t.cancel()
	t.device.Close()
	t.report(code, message)
}

// report logs message and ends Events with an "error" state.
func (t *tunnel) report(code domain.ErrorCode, message string) {
	t.driver.log(domain.LogLevelError, message)
	t.driver.emit(domain.StateEvent{State: domain.StateError, Code: code, Message: message, Since: t.driver.now()})
	t.driver.finish()
}

// stop ends the tunnel. A running device is removed at once; during the
// setup, run removes it as soon as the setup returns, which the cancelled
// context makes quick.
func (t *tunnel) stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped {
		return
	}
	t.stopped = true
	t.cancel()
	if t.device == nil {
		return
	}
	if t.stopPoll != nil {
		t.stopPoll()
	}
	t.closeDown(t.device)
}

// closeDown removes device, if any, reports "disconnected" and closes
// Events. The caller holds mu.
func (t *tunnel) closeDown(device Device) {
	if device != nil {
		device.Close()
		t.driver.log(domain.LogLevelInfo, "WireGuard device "+t.driver.opts.DeviceName+" removed")
	}
	t.driver.emit(domain.StateEvent{State: domain.StateDisconnected, Since: t.driver.now()})
	t.driver.finish()
}
