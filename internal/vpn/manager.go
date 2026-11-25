package vpn

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/netip"
	"sync"

	"tunneldeck/internal/domain"
)

// ErrClosed is returned by ConnectionManager methods after Shutdown.
var ErrClosed = errors.New("connection manager is shut down")

// ProfileSource reads profiles with their secrets; store.Store implements
// it and returns domain.ErrNotFound for unknown profiles.
type ProfileSource interface {
	ProfileWithSecrets(id string) (domain.Profile, error)
}

// DesiredStateStore persists the user's wish to be connected.
type DesiredStateStore interface {
	DesiredConnection() domain.DesiredConnection
	SetDesiredConnection(domain.DesiredConnection) error
}

// FirewallSource returns the firewall configuration to install.
type FirewallSource interface {
	Firewall() domain.Firewall
}

// NetGuard installs the firewall and routes through the tunnel;
// netguard.Guard implements it. RouteThroughTunnel also installs the
// policy routing of the firewall's outbound rules and port forwards;
// ClearTunnelRouting removes it.
type NetGuard interface {
	InstallFirewall(ctx context.Context, firewall domain.Firewall, uiPort int) error
	RouteThroughTunnel(ctx context.Context, vpnIP netip.Addr) error
	ClearTunnelRouting(ctx context.Context) error
}

// ManagerConfig holds the dependencies of a ConnectionManager.
type ManagerConfig struct {
	Registry *Registry
	Profiles ProfileSource
	Desired  DesiredStateStore
	Firewall FirewallSource
	Guard    NetGuard
	// UIPort is the web UI port, which a firewall rule never opens.
	UIPort int
	// Clock defaults to SystemClock. Daily reconnects use its time zone.
	Clock Clock
	// Random returns a value in [0, 1) for the backoff jitter; it defaults
	// to math/rand/v2.Float64.
	Random func() float64
}

func (c ManagerConfig) withDefaults() ManagerConfig {
	if c.Clock == nil {
		c.Clock = SystemClock{}
	}
	if c.Random == nil {
		c.Random = rand.Float64
	}
	return c
}

// ConnectionManager owns the single active tunnel (SPEC §4.1–4.3): it
// persists the desired state, starts and stops drivers, applies the
// firewall and the tunnel routing, retries with backoff, reconnects once a
// day when the profile asks for it, and fans events out to subscribers.
//
// All state lives in one goroutine; the methods send it commands. Commands
// return once applied; the connection itself progresses in the background
// and is reported through Status and Subscribe.
type ConnectionManager struct {
	commands chan func(*loop)
	done     chan struct{} // closed when the loop has ended
	final    Status        // written before done is closed
}

// NewConnectionManager returns a running manager in the disconnected state.
// Call Start to restore the persisted desired state and Shutdown to stop.
func NewConnectionManager(cfg ManagerConfig) *ConnectionManager {
	m := &ConnectionManager{commands: make(chan func(*loop)), done: make(chan struct{})}
	l := newLoop(cfg.withDefaults(), m.post)
	go m.run(l)
	return m
}

func (m *ConnectionManager) run(l *loop) {
	defer close(m.done)
	for !l.finished {
		command := <-m.commands
		command(l)
	}
	m.final = l.status
}

// post hands command to the loop from any goroutine except the loop's own.
// It reports false once the loop has ended.
func (m *ConnectionManager) post(command func(*loop)) bool {
	select {
	case m.commands <- command:
		return true
	case <-m.done:
		return false
	}
}

// call runs f in the loop and returns its result. ctx bounds only the wait
// for the loop to accept the command.
func (m *ConnectionManager) call(ctx context.Context, f func(*loop) error) error {
	result := make(chan error, 1)
	select {
	case m.commands <- func(l *loop) { result <- f(l) }:
		return <-result
	case <-m.done:
		return ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Start restores the persisted desired state: if it says connected, the
// tunnel comes up. Routing left over by a crashed run is cleared first.
func (m *ConnectionManager) Start(ctx context.Context) error {
	return m.call(ctx, (*loop).restore)
}

// Connect makes profileID the wanted connection and persists that. A
// tunnel of another profile is disconnected first; when the profile is
// already connecting or connected nothing happens. An unknown profile
// yields an error wrapping domain.ErrNotFound.
func (m *ConnectionManager) Connect(ctx context.Context, profileID string) error {
	return m.call(ctx, func(l *loop) error { return l.connect(profileID) })
}

// Disconnect persists that no connection is wanted and takes the tunnel
// down. It takes effect even when persisting fails; that error is
// returned.
func (m *ConnectionManager) Disconnect(ctx context.Context) error {
	return m.call(ctx, (*loop).disconnect)
}

// Reconnect stops and starts the wanted tunnel right away, also during a
// backoff pause or after a rejection. Without a wanted connection it fails
// with an error wrapping domain.ErrConflict.
func (m *ConnectionManager) Reconnect(ctx context.Context) error {
	return m.call(ctx, (*loop).reconnect)
}

// ProfileChanged tells the manager that a profile was saved or deleted. For
// the wanted profile it reschedules the daily reconnect and lifts a
// rejection, so the edited profile is tried at once; a deleted profile
// clears the desired state and disconnects.
func (m *ConnectionManager) ProfileChanged(id string) {
	m.post(func(l *loop) { l.profileChanged(id) })
}

// Status returns a snapshot of the connection.
func (m *ConnectionManager) Status() Status {
	result := make(chan Status, 1)
	if !m.post(func(l *loop) { result <- l.status }) {
		return m.final
	}
	return <-result
}

// Logs returns up to tail of the newest log lines, oldest first; tail <= 0
// returns all of them (at most 2000).
func (m *ConnectionManager) Logs(tail int) []domain.LogEvent {
	result := make(chan []domain.LogEvent, 1)
	if !m.post(func(l *loop) { result <- l.logs.tail(tail) }) {
		return nil
	}
	return <-result
}

// Subscribe returns a stream of state, traffic and log events. A
// subscriber that does not keep up is dropped: its channel is closed. The
// channel is also closed by cancel and by Shutdown.
func (m *ConnectionManager) Subscribe() (<-chan domain.Event, func()) {
	events := make(chan domain.Event, subscriberBuffer)
	result := make(chan int, 1)
	if !m.post(func(l *loop) { result <- l.subscribe(events) }) {
		close(events)
		return events, func() {}
	}
	id := <-result
	var once sync.Once
	cancel := func() {
		once.Do(func() { m.post(func(l *loop) { l.unsubscribe(id) }) })
	}
	return events, cancel
}

// Shutdown stops the tunnel and clears the routing without changing the
// persisted desired state, so the next Start reconnects. It waits until the
// tunnel is down or ctx ends.
func (m *ConnectionManager) Shutdown(ctx context.Context) error {
	if !m.post((*loop).shutdown) {
		return nil
	}
	select {
	case <-m.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
