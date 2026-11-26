package vpn

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"tunneldeck/internal/domain"
)

const (
	logCapacity      = 2000
	subscriberBuffer = 256
	// operationTimeout bounds every firewall, routing and driver start call.
	operationTimeout = 30 * time.Second
	// stopTimeout bounds a driver stop; drivers kill their process sooner.
	stopTimeout = 30 * time.Second
)

// Reasons the manager gives for its own state changes.
const (
	reasonDailyReconnect = "scheduled daily reconnect"
	reasonReconnect      = "reconnect requested"
)

// failure is why a tunnel attempt ended.
type failure struct {
	code    domain.ErrorCode
	message string
}

// retryable reports whether auto-retry may try again. A rejection by the
// server or an unusable profile waits for the user, so the account is not
// locked by the provider (SPEC §4.2).
func (f failure) retryable() bool {
	switch f.code {
	case domain.ErrorCodeAuthFailed, domain.ErrorCodeServerRejected, domain.ErrorCodeProfileInvalid:
		return false
	}
	return true
}

// tunnel is one driver instance from its start to its stop.
type tunnel struct {
	profileID string
	driver    Driver
	// remoteNetworks are routed through the tunnel while it is connected;
	// they are read once per attempt, like every other profile setting.
	remoteNetworks []netip.Prefix
	// vpnIP is the address of the last connected event.
	vpnIP    string
	quit     chan struct{} // closed when the tunnel is discarded
	stopping bool
	// failure is set when the tunnel failed and must be stopped.
	failure *failure
}

// timerSlot holds at most one pending timer. gen tells a firing timer
// whether it is still the current one.
type timerSlot struct {
	stop    func() bool
	pending bool
	gen     int
}

func (s *timerSlot) cancel() {
	if s.stop != nil {
		s.stop()
	}
	s.stop, s.pending = nil, false
	s.gen++
}

// dailyPlan is the scheduled daily reconnect of the wanted profile.
type dailyPlan struct {
	timer     timerSlot
	profileID string
	config    domain.DailyReconnect
	at        time.Time // next run
	lastRun   string    // calendar day of the last reconnect
}

type trafficSample struct {
	bytesIn, bytesOut uint64
	at                time.Time
	valid             bool
}

// loop is the state of a ConnectionManager. Only the manager's goroutine
// touches it; other goroutines reach it through post.
type loop struct {
	cfg  ManagerConfig
	post func(func(*loop)) bool

	// Desired state.
	want      bool
	profileID string
	blocked   bool // a rejection waits for the user or a profile change
	restart   bool // stop the running tunnel and start it again at once

	tunnel   *tunnel
	retry    timerSlot
	failures int // consecutive failed attempts, for the backoff
	daily    dailyPlan
	// routingRetry applies the routing of the connected tunnel again after
	// a failure; routingFailures counts the failures for its backoff.
	routingRetry    timerSlot
	routingFailures int
	// publicIP is the detection of the connected tunnel's public IP.
	publicIP publicIPDetection

	status         Status
	traffic        trafficSample
	logs           *logRing
	subscribers    map[int]chan<- domain.Event
	nextSubscriber int

	shuttingDown bool
	finished     bool
}

func newLoop(cfg ManagerConfig, post func(func(*loop)) bool) *loop {
	l := &loop{
		cfg:         cfg,
		post:        post,
		logs:        newLogRing(logCapacity),
		subscribers: make(map[int]chan<- domain.Event),
	}
	l.status = Status{State: domain.StateDisconnected, Since: l.now()}
	return l
}

// restore applies the persisted desired state once, unless a connection
// was already requested.
func (l *loop) restore() error {
	if l.shuttingDown {
		return ErrClosed
	}
	if l.tunnel == nil {
		l.clearRouting()
	}
	desired := l.cfg.Desired.DesiredConnection()
	if !desired.WantConnected || l.want {
		return nil
	}
	l.want, l.profileID = true, desired.ActiveProfileID
	l.logf(domain.LogLevelInfo, "restoring the connection wanted before the restart")
	l.reconcile()
	return nil
}

func (l *loop) connect(profileID string) error {
	if l.shuttingDown {
		return ErrClosed
	}
	if t := l.tunnel; l.want && t != nil && !t.stopping && t.profileID == profileID {
		return nil
	}
	if _, err := l.cfg.Profiles.ProfileWithSecrets(profileID); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	desired := domain.DesiredConnection{ActiveProfileID: profileID, WantConnected: true}
	if err := l.cfg.Desired.SetDesiredConnection(desired); err != nil {
		return fmt.Errorf("connect: persist desired state: %w", err)
	}
	l.want, l.profileID = true, profileID
	l.userAction()
	l.reconcile()
	return nil
}

func (l *loop) disconnect() error {
	if l.shuttingDown {
		return ErrClosed
	}
	err := l.cfg.Desired.SetDesiredConnection(domain.DesiredConnection{ActiveProfileID: l.profileID})
	l.want, l.restart = false, false
	l.userAction()
	l.cancelDaily()
	if l.tunnel == nil && l.status.State != domain.StateDisconnected {
		l.setState(domain.StateDisconnected, "")
	}
	l.reconcile()
	if err != nil {
		return fmt.Errorf("disconnect: persist desired state: %w", err)
	}
	return nil
}

func (l *loop) reconnect() error {
	if l.shuttingDown {
		return ErrClosed
	}
	if !l.want {
		return fmt.Errorf("reconnect: no connection is wanted: %w", domain.ErrConflict)
	}
	l.userAction()
	l.restart = true
	if t := l.tunnel; t != nil && !t.stopping {
		l.setState(domain.StateReconnecting, reasonReconnect)
	}
	l.reconcile()
	return nil
}

// userAction undoes the effects of earlier failures: a request of the user
// is tried at once.
func (l *loop) userAction() {
	l.blocked = false
	l.resetRetry()
	l.status.LastError = nil
}

func (l *loop) profileChanged(id string) {
	if l.shuttingDown {
		return
	}
	p, err := l.cfg.Profiles.ProfileWithSecrets(id)
	switch {
	case errors.Is(err, domain.ErrNotFound):
		l.profileDeleted(id)
	case err != nil:
		l.logf(domain.LogLevelWarn, "reading the changed profile: %v", err)
	default:
		l.profileUpdated(p)
	}
}

func (l *loop) profileDeleted(id string) {
	switch {
	case l.want && l.profileID == id:
		l.forgetProfile()
		l.reconcile()
	case l.tunnel == nil && l.status.ProfileID == id:
		l.status.ProfileID, l.status.ProfileName, l.status.Protocol = "", "", ""
	}
}

func (l *loop) profileUpdated(p domain.Profile) {
	if l.status.ProfileID == p.ID {
		l.status.ProfileName = p.Name
	}
	if !l.want || l.profileID != p.ID {
		return
	}
	l.planDaily(p)
	if l.tunnel == nil {
		l.blocked = false
		l.resetRetry()
		l.reconcile()
	}
}

// forgetProfile clears the desired state after the wanted profile was
// deleted.
func (l *loop) forgetProfile() {
	l.logf(domain.LogLevelWarn, "the profile was deleted, so no connection is wanted any more")
	if err := l.cfg.Desired.SetDesiredConnection(domain.DesiredConnection{}); err != nil {
		l.logf(domain.LogLevelError, "clearing the desired connection: %v", err)
	}
	l.want, l.profileID, l.blocked, l.restart = false, "", false, false
	l.resetRetry()
	l.cancelDaily()
	l.status.ProfileID, l.status.ProfileName, l.status.Protocol = "", "", ""
	l.status.LastError = nil
	if l.tunnel == nil {
		l.setState(domain.StateDisconnected, "")
	}
}

func (l *loop) shutdown() {
	if l.shuttingDown {
		return
	}
	l.shuttingDown = true
	l.want, l.restart = false, false
	l.resetRetry()
	l.cancelDaily()
	l.reconcile()
	l.finishShutdown()
}

// finishShutdown ends the loop once no tunnel is left.
func (l *loop) finishShutdown() {
	if !l.shuttingDown || l.tunnel != nil {
		return
	}
	if l.status.State != domain.StateDisconnected {
		l.setState(domain.StateDisconnected, "")
	}
	for id := range l.subscribers {
		l.unsubscribe(id)
	}
	l.finished = true
}

// reconcile moves the actual state one step towards the desired state.
// While a stop is in progress it waits for the stop to finish.
func (l *loop) reconcile() {
	if t := l.tunnel; t != nil {
		if !t.stopping && (!l.want || t.profileID != l.profileID || l.restart || t.failure != nil) {
			l.beginStop(t)
		}
		return
	}
	if l.want && !l.blocked && !l.retry.pending {
		l.startAttempt()
	}
}

// startAttempt runs one connection attempt: firewall, then driver start.
// The firewall is installed again every time because other software may
// have reordered the host chains; if that fails no process is started.
func (l *loop) startAttempt() {
	l.restart = false
	p, err := l.cfg.Profiles.ProfileWithSecrets(l.profileID)
	if errors.Is(err, domain.ErrNotFound) {
		l.forgetProfile()
		return
	}
	if err != nil {
		l.fail(failure{code: domain.ErrorCodeStartFailed, message: "reading the profile failed: " + err.Error()})
		return
	}
	l.planDaily(p)
	l.beginAttempt(p)
	factory, err := l.cfg.Registry.Lookup(p.Protocol)
	if err != nil {
		l.fail(failure{code: domain.ErrorCodeProfileInvalid, message: err.Error()})
		return
	}
	if err := l.installFirewall(); err != nil {
		l.fail(failure{code: domain.ErrorCodeFirewallFailed, message: "installing the firewall failed: " + err.Error()})
		return
	}
	l.launch(p, factory())
}

func (l *loop) beginAttempt(p domain.Profile) {
	l.status.ProfileID, l.status.ProfileName, l.status.Protocol = p.ID, p.Name, p.Protocol
	l.status.BytesIn, l.status.BytesOut, l.status.RateIn, l.status.RateOut = 0, 0, 0, 0
	l.status.DataCipher, l.status.ControlChannel = "", ""
	l.traffic = trafficSample{}
	if l.status.State != domain.StateReconnecting {
		l.setState(domain.StateConnecting, "")
	}
}

func (l *loop) launch(p domain.Profile, driver Driver) {
	t := &tunnel{profileID: p.ID, driver: driver, remoteNetworks: remoteNetworksOf(driver, p), quit: make(chan struct{})}
	l.tunnel = t
	go forwardEvents(l.post, t)
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	if err := driver.Start(ctx, p, Secrets(p.Secrets)); err != nil {
		t.failure = startFailure(err)
		l.reconcile()
	}
}

func startFailure(err error) *failure {
	if errors.Is(err, domain.ErrValidation) {
		return &failure{code: domain.ErrorCodeProfileInvalid, message: err.Error()}
	}
	return &failure{code: domain.ErrorCodeStartFailed, message: err.Error()}
}

// forwardEvents hands the driver's events to the loop until the driver
// closes its channel or the tunnel is discarded.
func forwardEvents(post func(func(*loop)) bool, t *tunnel) {
	events := t.driver.Events()
	for {
		select {
		case e, ok := <-events:
			if !ok {
				post(func(l *loop) { l.driverClosed(t) })
				return
			}
			if !post(func(l *loop) { l.driverEvent(t, e) }) {
				return
			}
		case <-t.quit:
			return
		}
	}
}

// beginStop stops the driver in the background so the loop stays
// responsive; stopped continues once the driver is down.
func (l *loop) beginStop(t *tunnel) {
	t.stopping = true
	l.publicIP.stop()
	if t.failure == nil && !l.restart {
		l.setState(domain.StateDisconnecting, "")
	}
	post := l.post
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), stopTimeout)
		defer cancel()
		err := t.driver.Stop(ctx)
		post(func(l *loop) { l.stopped(t, err) })
	}()
}

func (l *loop) stopped(t *tunnel, err error) {
	close(t.quit)
	l.tunnel = nil
	if err != nil {
		l.logf(domain.LogLevelWarn, "stopping the tunnel: %v", err)
	}
	l.resetRoutingRetry()
	l.status.RoutingWarning = nil
	l.clearRouting()
	switch {
	case !l.want:
		l.setState(domain.StateDisconnected, "")
	case l.restart:
		// reconcile starts the tunnel again without backoff
	case t.failure != nil && t.profileID == l.profileID:
		l.fail(*t.failure)
	}
	l.reconcile()
	l.finishShutdown()
}

// fail records f and either schedules a retry or waits for the user.
func (l *loop) fail(f failure) {
	l.status.LastError = &StatusError{Code: f.code, Message: f.message, Time: l.now()}
	l.setState(domain.StateError, f.message)
	if !f.retryable() {
		l.blocked = true
		l.logf(domain.LogLevelError, "%s; not retrying until the profile changes or a new connect", f.message)
		return
	}
	delay := l.scheduleRetry()
	l.logf(domain.LogLevelError, "%s; retrying in %s", f.message, delay)
}

func (l *loop) scheduleRetry() time.Duration {
	delay := backoffDelay(l.failures, l.cfg.Random)
	l.failures++
	l.arm(&l.retry, delay, (*loop).reconcile)
	return delay
}

func (l *loop) resetRetry() {
	l.retry.cancel()
	l.failures = 0
}

func (l *loop) resetRoutingRetry() {
	l.routingRetry.cancel()
	l.routingFailures = 0
}

// arm replaces the timer in slot with one that runs fire in the loop
// after d.
func (l *loop) arm(slot *timerSlot, d time.Duration, fire func(*loop)) {
	slot.cancel()
	gen := slot.gen
	slot.pending = true
	post := l.post
	slot.stop = l.cfg.Clock.AfterFunc(d, func() {
		post(func(l *loop) {
			if slot.gen != gen {
				return
			}
			slot.stop, slot.pending = nil, false
			fire(l)
		})
	})
}
