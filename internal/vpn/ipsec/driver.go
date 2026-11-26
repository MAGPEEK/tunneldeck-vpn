package ipsec

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"path"
	"sync"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

// Defaults of Options. The Dockerfile builds charon with its PID file in
// DefaultRuntimeDir/ipsec, next to the files the driver writes.
const (
	DefaultRuntimeDir = "/run/tunneldeck"
	DefaultBinary     = "/usr/lib/strongswan/charon"
)

const (
	runtimeSubdir  = "ipsec"
	configFileName = "strongswan.conf"
	socketFileName = "charon.vici"
	pidFileName    = "charon.pid"

	runtimeDirMode fs.FileMode = 0o700
	configFileMode fs.FileMode = 0o600

	eventBuffer = 64
	// lanCheckTimeout bounds the LAN detection of Validate.
	lanCheckTimeout = 5 * time.Second
)

// Options configure the IPsec driver. Zero values select the defaults;
// DeviceName (netguard.DeviceName) and Runner are required to start a
// tunnel. Without LANSubnets, Validate cannot check the subnets against
// the LAN; netguard still refuses to route remote subnets that overlap it.
type Options struct {
	RuntimeDir string
	DeviceName string
	Binary     string
	Runner     CommandRunner
	Starter    ProcessStarter
	Dialer     Dialer
	FileSystem FileSystem
	Clock      vpn.Clock
	LANSubnets LANSource
}

func (o Options) withDefaults() Options {
	if o.RuntimeDir == "" {
		o.RuntimeDir = DefaultRuntimeDir
	}
	if o.Binary == "" {
		o.Binary = DefaultBinary
	}
	if o.Starter == nil {
		o.Starter = execStarter{}
	}
	if o.Dialer == nil {
		o.Dialer = unixDialer{}
	}
	if o.FileSystem == nil {
		o.FileSystem = osFileSystem{}
	}
	if o.Clock == nil {
		o.Clock = vpn.SystemClock{}
	}
	return o
}

// Factory returns the registry factory of the IPsec driver.
func Factory(opts Options) vpn.Factory {
	return func() vpn.Driver { return New(opts) }
}

// Driver implements vpn.Driver for IPsec/IKEv2. One Driver serves one
// charon lifetime: Start may be called once, and Events is closed once
// charon has exited and its files are removed. Within that lifetime
// charon keeps the tunnel up (retries, DPD, rekeying); the driver reports
// what happens and ends the tunnel on failures that need the user.
type Driver struct {
	opts     Options
	events   chan domain.Event
	stopping chan struct{} // closed by the first Stop
	done     chan struct{} // closed together with events

	finishOnce sync.Once

	mu            sync.Mutex
	started       bool
	stopRequested bool
	process       Process // set once charon runs
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

// Protocol returns domain.ProtocolIPsec.
func (*Driver) Protocol() domain.Protocol { return domain.ProtocolIPsec }

// Describe returns the profile form of the driver.
func (*Driver) Describe() vpn.FormSchema { return Describe() }

// Validate checks the IPsec settings and secrets of p, and its subnets
// against the host's LAN when the LAN is known.
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

// Advise returns the advisories of p's settings.
func (*Driver) Advise(p domain.PublicProfile) []vpn.Advisory { return Advise(p) }

// AdviseSecrets returns the advisories that depend on secret values.
func (*Driver) AdviseSecrets(p domain.Profile) []vpn.Advisory { return AdviseSecrets(p) }

// RemoteNetworks returns the remote subnets of p other than 0.0.0.0/0
// (vpn.RemoteNetworker).
func (*Driver) RemoteNetworks(p domain.Profile) []netip.Prefix { return RemoteNetworks(p) }

// LocalNetworks returns the local subnets of a net-to-net profile
// (vpn.LocalNetworker).
func (*Driver) LocalNetworks(p domain.Profile) []netip.Prefix { return LocalNetworks(p) }

// Events streams state, traffic, channel and log events until charon has
// exited. The last state event is "disconnected" after Stop, or "error"
// with a domain.ErrorCode.
func (d *Driver) Events() <-chan domain.Event { return d.events }

// Start checks the profile and returns; everything that may wait runs in
// the background (tunnel.run): writing charon's configuration, starting
// charon, taking over its TUN device as the tunnel device, loading the
// credentials and the connection over VICI and initiating it. Failures of
// these steps are reported through Events as an "error" state.
func (d *Driver) Start(ctx context.Context, p domain.Profile, s vpn.Secrets) error {
	if err := d.claimStart(); err != nil {
		return err
	}
	t, err := d.prepare(ctx, p, s)
	if err != nil {
		d.finish()
		return fmt.Errorf("start ipsec: %w", err)
	}
	go t.run()
	return nil
}

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
	return newTunnel(d, config, RemoteNetworks(p)), nil
}

func (d *Driver) claimStart() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case d.started:
		return errors.New("start ipsec: the driver was started before")
	case d.stopRequested:
		return errors.New("start ipsec: the driver was stopped")
	}
	d.started = true
	return nil
}

// Stop ends the tunnel and returns once charon has exited and the files
// are removed: the IKE SA is deleted over VICI, charon gets SIGTERM and,
// after 10 s, SIGKILL; when ctx ends first, SIGKILL at once. Stop may be
// called more than once, also without Start.
func (d *Driver) Stop(ctx context.Context) error {
	if !d.requestStop() {
		d.finish()
		return nil
	}
	select {
	case <-d.done:
		return nil
	case <-ctx.Done():
	}
	d.kill()
	select {
	case <-d.done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("stop ipsec: charon did not exit: %w", ctx.Err())
	}
}

// requestStop marks the stop and reports whether the driver was started.
func (d *Driver) requestStop() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.stopRequested {
		d.stopRequested = true
		close(d.stopping)
	}
	return d.started
}

func (d *Driver) wasStopRequested() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stopRequested
}

func (d *Driver) attachProcess(p Process) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.process = p
}

// kill sends SIGKILL to charon, if it runs.
func (d *Driver) kill() {
	d.mu.Lock()
	process := d.process
	d.mu.Unlock()
	if process != nil {
		_ = process.Kill()
	}
}

func (d *Driver) runtimeDir() string { return path.Join(d.opts.RuntimeDir, runtimeSubdir) }
func (d *Driver) configPath() string { return path.Join(d.runtimeDir(), configFileName) }
func (d *Driver) socketPath() string { return path.Join(d.runtimeDir(), socketFileName) }

// runtimeFiles are the files of one charon run: the configuration, the
// VICI socket and the PID file.
func (d *Driver) runtimeFiles() []string {
	return []string{d.configPath(), d.socketPath(), path.Join(d.runtimeDir(), pidFileName)}
}

// writeConfig creates the runtime directory with mode 0700 and writes a
// fresh strongswan.conf with mode 0600. Files left by a crashed run are
// removed first, so a stale PID file cannot keep charon from starting.
func (d *Driver) writeConfig() error {
	fsys := d.opts.FileSystem
	if err := fsys.MkdirAll(d.runtimeDir(), runtimeDirMode); err != nil {
		return fmt.Errorf("create runtime directory: %w", err)
	}
	if err := fsys.Chmod(d.runtimeDir(), runtimeDirMode); err != nil {
		return fmt.Errorf("restrict runtime directory: %w", err)
	}
	if err := d.removeFiles(); err != nil {
		return err
	}
	if err := fsys.WriteFile(d.configPath(), []byte(renderStrongswanConf(d.socketPath())), configFileMode); err != nil {
		return fmt.Errorf("write strongswan.conf: %w", err)
	}
	return nil
}

// removeFiles deletes the files of the run. Absent files are fine.
func (d *Driver) removeFiles() error {
	var errs []error
	for _, name := range d.runtimeFiles() {
		if err := d.opts.FileSystem.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// emit delivers e. Once a stop is requested nobody may be reading any more,
// so a full channel then drops the event instead of blocking.
func (d *Driver) emit(e domain.Event) {
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

func (d *Driver) log(level domain.LogLevel, text string) {
	d.emit(domain.LogEvent{Time: d.now(), Level: level, Text: text})
}

// finish closes Events and marks the driver done. Every emitter has
// returned when it is called.
func (d *Driver) finish() {
	d.finishOnce.Do(func() {
		close(d.events)
		close(d.done)
	})
}

func (d *Driver) now() time.Time { return d.opts.Clock.Now().UTC() }
