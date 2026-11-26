package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

const (
	eventBuffer = 64
	// lanCheckTimeout bounds the LAN detection of Validate.
	lanCheckTimeout = 5 * time.Second
)

// Options configure the WireGuard driver. Zero values select the defaults;
// DeviceName (netguard.DeviceName) and Runner are required to start a
// tunnel. Without LANSubnets, Validate cannot reject allowed IPs that
// overlap the LAN; netguard still refuses to route them.
type Options struct {
	DeviceName string
	Runner     CommandRunner
	// Opener defaults to the embedded wireguard-go on Linux.
	Opener DeviceOpener
	// Resolver defaults to the host's resolver.
	Resolver   Resolver
	Clock      vpn.Clock
	LANSubnets LANSource
}

func (o Options) withDefaults() Options {
	if o.Opener == nil {
		o.Opener = defaultOpener()
	}
	if o.Resolver == nil {
		o.Resolver = net.DefaultResolver
	}
	if o.Clock == nil {
		o.Clock = vpn.SystemClock{}
	}
	return o
}

// Factory returns the registry factory of the WireGuard driver.
func Factory(opts Options) vpn.Factory {
	return func() vpn.Driver { return New(opts) }
}

// Driver implements vpn.Driver for WireGuard. One Driver serves one device
// lifetime: Start may be called once, and Events is closed once the device
// is gone. It reports outcomes as events; within one tunnel it keeps
// trying the handshake and resolves the endpoint again as SPEC §18 asks.
type Driver struct {
	opts     Options
	events   chan domain.Event
	stopping chan struct{} // closed by the first Stop
	done     chan struct{} // closed together with events

	// emitMu guards finished: emitters hold it shared, finish exclusively,
	// so nothing is sent on the closed events channel.
	emitMu   sync.RWMutex
	finished bool

	mu            sync.Mutex
	started       bool
	stopRequested bool
	tunnel        *tunnel // set once the device runs
}

// New returns a stopped driver.
func New(opts Options) *Driver {
	return &Driver{
		opts:     opts.withDefaults(),
		events:   make(chan domain.Event, eventBuffer),
		stopping: make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// Protocol returns domain.ProtocolWireGuard.
func (*Driver) Protocol() domain.Protocol { return domain.ProtocolWireGuard }

// Describe returns the profile form of the driver.
func (*Driver) Describe() vpn.FormSchema { return Describe() }

// Validate checks the WireGuard settings and secrets of p, and that its
// allowed IPs stay clear of the host's LAN when the LAN is known.
func (d *Driver) Validate(p domain.Profile) error { return ValidateWithLAN(p, d.lan()) }

// lan returns the host's LAN subnets, or nil when they cannot be detected:
// then netguard's check at connect time is the only one.
func (d *Driver) lan() []netip.Prefix {
	if d.opts.LANSubnets == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), lanCheckTimeout)
	defer cancel()
	lan, err := d.opts.LANSubnets(ctx)
	if err != nil {
		return nil
	}
	return lan
}

// Advise returns no advisories: WireGuard has no legacy settings.
func (*Driver) Advise(domain.PublicProfile) []vpn.Advisory { return nil }

// RemoteNetworks returns the allowed IPs of p other than 0.0.0.0/0
// (vpn.RemoteNetworker).
func (*Driver) RemoteNetworks(p domain.Profile) []netip.Prefix { return RemoteNetworks(p) }

// GenerateKeyPair returns a new private key and its public key in base64.
// Nothing is stored.
func (*Driver) GenerateKeyPair() (privateKey, publicKey string, err error) {
	return GenerateKeyPair()
}

// Derive returns the values shown with a stored profile that come from its
// secrets: the public key of its private key. Nothing secret is returned.
func (*Driver) Derive(p domain.Profile) map[string]string {
	public, err := PublicKeyOf(p.Secrets[SecretPrivateKey])
	if err != nil {
		return nil
	}
	return map[string]string{DerivedPublicKey: public}
}

// Events streams state, traffic, channel and log events until the device
// is gone. The last state event is "disconnected" after Stop, or "error"
// when the device failed.
func (d *Driver) Events() <-chan domain.Event { return d.events }

// Start checks the profile and returns; everything that may wait runs in
// the background (tunnel.run), so the caller stays responsive: resolving
// the endpoint, creating the device on the tunnel interface, giving the
// interface its address, MTU and link and configuring the server as the
// device's peer, then waiting for the handshake. Failures of these steps
// are reported through Events as an "error" state.
func (d *Driver) Start(ctx context.Context, p domain.Profile, s vpn.Secrets) error {
	if err := d.claimStart(); err != nil {
		return err
	}
	t, err := d.prepare(ctx, p, s)
	if err != nil {
		d.finish()
		return fmt.Errorf("start wireguard: %w", err)
	}
	if d.attach(t) {
		d.finish()
		return nil
	}
	go t.run()
	return nil
}

// prepare checks the profile and the options and returns the tunnel to
// run.
func (d *Driver) prepare(ctx context.Context, p domain.Profile, s vpn.Secrets) (*tunnel, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	config, problems := parseProfile(p, s, nil)
	if err := problems.OrNil(); err != nil {
		return nil, err
	}
	if d.opts.Runner == nil || d.opts.DeviceName == "" {
		return nil, errors.New("the driver has no device name or command runner")
	}
	return newTunnel(d, config), nil
}

func (d *Driver) claimStart() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case d.started:
		return errors.New("start wireguard: the driver was started before")
	case d.stopRequested:
		return errors.New("start wireguard: the driver was stopped")
	}
	d.started = true
	return nil
}

// configure gives the interface its address, MTU and link through ip and
// the device its keys and peer through the UAPI. The address is added as
// a host address (/32), so the kernel adds no route to the main table: the
// tunnel is reached through table 7194 only (policy rules of netguard).
func (d *Driver) configure(ctx context.Context, device Device, c profileConfig, server netip.AddrPort) error {
	name := d.opts.DeviceName
	if _, err := d.opts.Runner.Run(ctx, "ip", "address", "add", hostAddress(c.address).String(), "dev", name); err != nil {
		return fmt.Errorf("set the tunnel address: %w", err)
	}
	if _, err := d.opts.Runner.Run(ctx, "ip", "link", "set", "dev", name, "mtu", strconv.Itoa(c.mtu), "up"); err != nil {
		return fmt.Errorf("bring the tunnel interface up: %w", err)
	}
	if err := device.IpcSet(renderConfig(c, server)); err != nil {
		return fmt.Errorf("configure the WireGuard device: %w", err)
	}
	return nil
}

// hostAddress is the interface address as a single-address prefix.
func hostAddress(address netip.Prefix) netip.Prefix {
	return netip.PrefixFrom(address.Addr(), address.Addr().BitLen())
}

// deviceLog forwards the device's log lines to Events without waiting
// for a reader (tryEmit).
func (d *Driver) deviceLog() DeviceLog {
	return DeviceLog{
		Verbose: func(text string) {
			if level, line, keep := verboseLine(text); keep {
				d.tryLog(level, line)
			}
		},
		Error: func(text string) { d.tryLog(errorLine(text)) },
	}
}

// attach publishes the running tunnel to Stop and reports whether a stop
// was requested before it existed.
func (d *Driver) attach(t *tunnel) (stopRequested bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tunnel = t
	return d.stopRequested
}

// Stop removes the device and returns once Events is closed. Stop may be
// called more than once, also without Start.
func (d *Driver) Stop(ctx context.Context) error {
	t, started := d.requestStop()
	if !started {
		d.finish()
		return nil
	}
	if t != nil {
		t.stop()
	}
	select {
	case <-d.done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("stop wireguard: the device did not go away: %w", ctx.Err())
	}
}

func (d *Driver) requestStop() (*tunnel, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.stopRequested {
		d.stopRequested = true
		close(d.stopping)
	}
	return d.tunnel, d.started
}

func (d *Driver) log(level domain.LogLevel, text string) {
	d.emit(domain.LogEvent{Time: d.now(), Level: level, Text: text})
}

func (d *Driver) tryLog(level domain.LogLevel, text string) {
	d.tryEmit(domain.LogEvent{Time: d.now(), Level: level, Text: text})
}

// tryEmit delivers e unless the channel is full. wireguard-go logs from its
// packet goroutines, and Start runs in the goroutine that reads the events
// only after Start returns, so neither may wait for a reader.
func (d *Driver) tryEmit(e domain.Event) {
	d.emitMu.RLock()
	defer d.emitMu.RUnlock()
	if d.finished {
		return
	}
	select {
	case d.events <- e:
	default:
	}
}

// emit delivers e. Once a stop is requested nobody may be reading any more,
// so a full channel then drops the event instead of blocking. After finish
// events are dropped: wireguard-go may still log while it shuts down.
func (d *Driver) emit(e domain.Event) {
	d.emitMu.RLock()
	defer d.emitMu.RUnlock()
	if d.finished {
		return
	}
	select {
	case d.events <- e:
		return
	default:
	}
	select {
	case d.events <- e:
	case <-d.stopping:
	}
}

// finish closes Events and marks the driver done.
func (d *Driver) finish() {
	d.emitMu.Lock()
	defer d.emitMu.Unlock()
	if d.finished {
		return
	}
	d.finished = true
	close(d.events)
	close(d.done)
}

func (d *Driver) now() time.Time { return d.opts.Clock.Now().UTC() }
