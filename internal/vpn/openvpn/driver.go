package openvpn

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sync"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

// Defaults of Options.
const (
	DefaultRuntimeDir = "/run/tunneldeck"
	DefaultBinary     = "openvpn"
)

const (
	configFileName = "openvpn.conf"
	socketFileName = "mgmt.sock"

	runtimeDirMode fs.FileMode = 0o700
	configFileMode fs.FileMode = 0o600

	// socketPollInterval and socketWaitTimeout bound the wait for the
	// management socket after the spawn.
	socketPollInterval = 100 * time.Millisecond
	socketWaitTimeout  = 10 * time.Second
	// terminateTimeout is the grace period between "signal SIGTERM" and
	// SIGKILL (docs/openvpn-notes.md, implementation item 15).
	terminateTimeout = 10 * time.Second
	// maxHoldDelay caps the pause before an internal reconnect at the
	// backoff maximum of SPEC §4.2.
	maxHoldDelay = 60 * time.Second

	eventBuffer = 64
)

// Options configure the OpenVPN driver. Zero values select the defaults;
// DeviceName is required and must be netguard.DeviceName.
type Options struct {
	RuntimeDir string
	DeviceName string
	Binary     string
	Starter    ProcessStarter
	Dialer     Dialer
	FileSystem FileSystem
	Clock      vpn.Clock
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

// Factory returns the registry factory of the OpenVPN driver.
func Factory(opts Options) vpn.Factory {
	return func() vpn.Driver { return New(opts) }
}

// Driver implements vpn.Driver for OpenVPN. One Driver serves one process
// lifetime: Start may be called once, and Events is closed after the
// process has ended and its files are removed. It reports outcomes as
// events and never retries on its own.
type Driver struct {
	opts       Options
	events     chan domain.Event
	stopping   chan struct{} // closed by the first Stop
	done       chan struct{} // closed together with events
	finishOnce sync.Once

	mu            sync.Mutex
	started       bool
	stopRequested bool
	process       Process
	commands      *commandWriter // non-nil once the management socket is connected
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

// Protocol returns domain.ProtocolOpenVPN.
func (*Driver) Protocol() domain.Protocol { return domain.ProtocolOpenVPN }

// Describe returns the profile form of the driver.
func (*Driver) Describe() vpn.FormSchema { return Describe() }

// Validate checks the OpenVPN settings and secrets of p.
func (*Driver) Validate(p domain.Profile) error { return Validate(p) }

// Events streams state, traffic and log events until the process has ended.
// The last state event is "disconnected" after a requested stop or a clean
// exit, or "error" with a domain.ErrorCode.
func (d *Driver) Events() <-chan domain.Event { return d.events }

// Start renders the config for p into the runtime directory and spawns
// openvpn. Connecting to the management interface and the dialogue run in
// the background and are reported through Events. Passwords and the key
// passphrase go over management only.
func (d *Driver) Start(ctx context.Context, p domain.Profile, s vpn.Secrets) error {
	if err := d.claimStart(); err != nil {
		return err
	}
	r, err := d.launch(ctx, p, s)
	if err != nil {
		d.finish()
		return fmt.Errorf("start openvpn: %w", err)
	}
	go r.supervise()
	return nil
}

func (d *Driver) claimStart() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case d.started:
		return errors.New("start openvpn: the driver was started before")
	case d.stopRequested:
		return errors.New("start openvpn: the driver was stopped")
	}
	d.started = true
	return nil
}

func (d *Driver) launch(ctx context.Context, p domain.Profile, s vpn.Secrets) (*run, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	options := RenderOptions{ManagementSocket: d.socketPath(), DeviceName: d.opts.DeviceName}
	config, warnings, err := Render(p, s, options)
	if err != nil {
		return nil, err
	}
	if err := d.writeConfig(config); err != nil {
		return nil, errors.Join(err, d.removeFiles())
	}
	process, err := d.opts.Starter.Start(d.opts.Binary, "--config", d.configPath())
	if err != nil {
		return nil, errors.Join(err, d.removeFiles())
	}
	d.mu.Lock()
	d.process = process
	d.mu.Unlock()
	return newRun(d, process, managementCredentialsOf(p, s), warnings), nil
}

// writeConfig creates the runtime directory with mode 0700 and writes a
// fresh config file with mode 0600. Files left by a crashed run are
// removed first.
func (d *Driver) writeConfig(config string) error {
	fsys := d.opts.FileSystem
	if err := fsys.MkdirAll(d.opts.RuntimeDir, runtimeDirMode); err != nil {
		return fmt.Errorf("create runtime directory: %w", err)
	}
	if err := fsys.Chmod(d.opts.RuntimeDir, runtimeDirMode); err != nil {
		return fmt.Errorf("restrict runtime directory: %w", err)
	}
	if err := d.removeFiles(); err != nil {
		return err
	}
	if err := fsys.WriteFile(d.configPath(), []byte(config), configFileMode); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// removeFiles deletes the rendered config, which may hold key material,
// and the management socket. Absent files are fine.
func (d *Driver) removeFiles() error {
	var errs []error
	for _, name := range []string{d.configPath(), d.socketPath()} {
		if err := d.opts.FileSystem.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

func (d *Driver) configPath() string { return path.Join(d.opts.RuntimeDir, configFileName) }
func (d *Driver) socketPath() string { return path.Join(d.opts.RuntimeDir, socketFileName) }

// Stop ends the process and returns once it has exited and its files are
// removed. openvpn gets "signal SIGTERM" over management, so it can notify
// the server, and SIGKILL after 10 s or when ctx ends. Before the
// management interface is up openvpn is still held and is killed at once.
// Stop may be called more than once, also without Start.
func (d *Driver) Stop(ctx context.Context) error {
	commands, started := d.requestStop()
	if !started {
		d.finish()
		return nil
	}
	go d.terminate(commands)
	return d.awaitExit(ctx)
}

func (d *Driver) requestStop() (*commandWriter, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.stopRequested {
		d.stopRequested = true
		close(d.stopping)
	}
	return d.commands, d.started
}

// terminate runs in its own goroutine: a management write must never keep
// Stop from reaching the SIGKILL deadline.
func (d *Driver) terminate(commands *commandWriter) {
	if commands != nil && commands.command(commandSignalTerm) == nil {
		return
	}
	d.kill()
}

func (d *Driver) awaitExit(ctx context.Context) error {
	timeout := make(chan struct{})
	stopTimer := d.opts.Clock.AfterFunc(terminateTimeout, func() { close(timeout) })
	defer stopTimer()
	select {
	case <-d.done:
		return nil
	case <-timeout:
	case <-ctx.Done():
	}
	d.kill()
	select {
	case <-d.done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("stop openvpn: the process did not exit: %w", ctx.Err())
	}
}

// kill sends SIGKILL. Without a process the start is still in progress; the
// supervisor kills it as soon as it sees the stop.
func (d *Driver) kill() {
	d.mu.Lock()
	process := d.process
	d.mu.Unlock()
	if process != nil {
		_ = process.Kill()
	}
}

// attachCommands publishes the management connection to Stop and reports
// whether a stop was requested before it existed.
func (d *Driver) attachCommands(commands *commandWriter) (stopRequested bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.commands = commands
	return d.stopRequested
}

func (d *Driver) wasStopRequested() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stopRequested
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

// finish closes Events and marks the driver done. Every emitter has
// returned when it is called.
func (d *Driver) finish() {
	d.finishOnce.Do(func() {
		close(d.events)
		close(d.done)
	})
}
