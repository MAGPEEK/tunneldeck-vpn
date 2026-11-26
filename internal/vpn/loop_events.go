package vpn

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"time"

	"tunneldeck/internal/domain"
)

// This file holds how the loop reacts to driver events and timers and how it
// reports state, traffic and log lines to subscribers.

func (l *loop) driverEvent(t *tunnel, e domain.Event) {
	if l.tunnel != t {
		return
	}
	switch e := e.(type) {
	case domain.LogEvent:
		l.appendLog(e)
	case domain.TrafficEvent:
		l.updateTraffic(e)
	case domain.ChannelEvent:
		l.updateChannel(e)
	case domain.StateEvent:
		if !t.stopping {
			l.driverState(t, e)
		}
	}
}

func (l *loop) driverState(t *tunnel, e domain.StateEvent) {
	switch e.State {
	case domain.StateConnecting:
		l.driverConnecting(e)
	case domain.StateConnected:
		l.tunnelConnected(t, e)
	case domain.StateReconnecting:
		l.setState(domain.StateReconnecting, e.Message)
	case domain.StateDisconnected, domain.StateError:
		t.failure = endFailure(e)
		l.reconcile()
	}
}

// driverConnecting shows the driver's note about an attempt that makes no
// progress yet, such as a server that does not answer. The state and its
// since stay; a later state change clears the note.
func (l *loop) driverConnecting(e domain.StateEvent) {
	if l.status.State != domain.StateConnecting && l.status.State != domain.StateReconnecting {
		return
	}
	l.status.Message, l.status.MessageCode = e.Message, e.MessageCode
	l.broadcast(l.stateEvent())
}

// endFailure turns the terminal event of a tunnel the manager did not stop
// into a failure. A clean exit nobody asked for is retried like a crash.
func endFailure(e domain.StateEvent) *failure {
	if e.State == domain.StateError && e.Code != "" {
		return &failure{code: e.Code, message: e.Message}
	}
	message := "the tunnel ended unexpectedly"
	if e.Message != "" {
		message += ": " + e.Message
	}
	return &failure{code: domain.ErrorCodeProcessFailed, message: message}
}

func (l *loop) driverClosed(t *tunnel) {
	if l.tunnel != t || t.stopping {
		return
	}
	t.failure = &failure{code: domain.ErrorCodeProcessFailed, message: "the driver stopped without reporting why"}
	l.reconcile()
}

// tunnelConnected routes replies and the remote networks through the
// tunnel on every connected event, because the VPN IP can change, and
// then, once routed, detects the public IP through it. A routing failure
// never takes a working tunnel down (applyRouting).
func (l *loop) tunnelConnected(t *tunnel, e domain.StateEvent) {
	t.vpnIP, t.noInternet = e.VPNIP, e.NoInternet
	l.resetRoutingRetry()
	l.applyRouting(t)
	l.failures = 0
	l.status.LastError = nil
	l.status.VPNIP, l.status.Remote = e.VPNIP, e.Remote
	l.setStateSince(domain.StateConnected, "", l.connectedSince(e))
	if l.status.RoutingWarning == nil {
		l.detectPublicIP(t)
	} else {
		l.setPublicIP("")
	}
}

// connectedSince is when the tunnel of e came up: the driver's time, such
// as WireGuard's handshake, unless it is unset or lies in the future.
func (l *loop) connectedSince(e domain.StateEvent) time.Time {
	now := l.now()
	if e.Since.IsZero() || e.Since.After(now) {
		return now
	}
	return e.Since.UTC()
}

// applyRouting routes through the connected tunnel t. When that fails, t
// stays up: the status carries a routing warning whose message names the
// failing command and its output, the log line too, and the routing is
// retried with the backoff of SPEC §4.2 for as long as t stays connected.
func (l *loop) applyRouting(t *tunnel) {
	err := l.routeThroughTunnel(t)
	if err == nil {
		if l.status.RoutingWarning != nil {
			l.status.RoutingWarning = nil
			l.logf(domain.LogLevelInfo, "the tunnel routing is applied")
		}
		return
	}
	message := "applying the tunnel routing failed: " + err.Error()
	l.status.RoutingWarning = &StatusError{Code: domain.ErrorCodeRoutingFailed, Message: message, Time: l.now()}
	delay := backoffDelay(l.routingFailures, l.cfg.Random)
	l.routingFailures++
	l.arm(&l.routingRetry, delay, func(l *loop) { l.retryRouting(t) })
	l.logf(domain.LogLevelError, "%s; the tunnel stays up, retrying the routing in %s", message, delay)
}

// retryRouting applies the routing again while t is the connected tunnel;
// otherwise the next connected event does. Success is announced with the
// unchanged state, so subscribers fetch the status without the warning, and
// the public IP is detected now that connections from the VPN IP use the
// tunnel.
func (l *loop) retryRouting(t *tunnel) {
	if l.tunnel != t || t.stopping || l.status.State != domain.StateConnected {
		return
	}
	l.applyRouting(t)
	if l.status.RoutingWarning == nil {
		l.broadcast(l.stateEvent())
		l.detectPublicIP(t)
	}
}

// updateChannel records what the tunnel negotiated.
func (l *loop) updateChannel(e domain.ChannelEvent) {
	if e.DataCipher != "" {
		l.status.DataCipher = e.DataCipher
	}
	if e.ControlChannel != "" {
		l.status.ControlChannel = e.ControlChannel
	}
	l.broadcast(e)
}

func (l *loop) installFirewall() error {
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	return l.cfg.Guard.InstallFirewall(ctx, l.cfg.Firewall.Firewall(), l.cfg.UIPort)
}

// routeThroughTunnel routes through t. A tunnel that carries local networks
// has no VPN IP of its own; every other tunnel must report one.
func (l *loop) routeThroughTunnel(t *tunnel) error {
	var ip netip.Addr
	if t.vpnIP != "" || len(t.localNetworks) == 0 {
		parsed, err := netip.ParseAddr(t.vpnIP)
		if err != nil {
			return fmt.Errorf("the driver reported no valid VPN IP (%q)", t.vpnIP)
		}
		ip = parsed
	}
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	return l.cfg.Guard.RouteThroughTunnel(ctx, ip, t.remoteNetworks, t.localNetworks)
}

func (l *loop) clearRouting() {
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	if err := l.cfg.Guard.ClearTunnelRouting(ctx); err != nil {
		l.logf(domain.LogLevelError, "clearing the tunnel routing failed: %v", err)
	}
}

// updateTraffic computes rates as byte deltas over the time between two
// traffic events.
func (l *loop) updateTraffic(e domain.TrafficEvent) {
	now := l.cfg.Clock.Now()
	if elapsed := now.Sub(l.traffic.at).Seconds(); l.traffic.valid && elapsed > 0 {
		l.status.RateIn = rate(e.BytesIn, l.traffic.bytesIn, elapsed)
		l.status.RateOut = rate(e.BytesOut, l.traffic.bytesOut, elapsed)
	}
	l.traffic = trafficSample{bytesIn: e.BytesIn, bytesOut: e.BytesOut, at: now, valid: true}
	l.status.BytesIn, l.status.BytesOut = e.BytesIn, e.BytesOut
	l.broadcast(domain.TrafficEvent{
		BytesIn: e.BytesIn, BytesOut: e.BytesOut, RateIn: l.status.RateIn, RateOut: l.status.RateOut,
	})
}

func rate(current, previous uint64, seconds float64) uint64 {
	if current < previous {
		return 0
	}
	return uint64(math.Round(float64(current-previous) / seconds))
}

// planDaily schedules the daily reconnect of p unless that plan stands.
func (l *loop) planDaily(p domain.Profile) {
	if l.daily.profileID == p.ID && l.daily.config == p.DailyReconnect {
		return
	}
	l.daily.timer.cancel()
	l.daily.profileID, l.daily.config = p.ID, p.DailyReconnect
	l.armDaily()
}

func (l *loop) armDaily() {
	if !l.daily.config.Enabled {
		return
	}
	now := l.cfg.Clock.Now()
	next, err := nextDailyRun(now, l.daily.config.Time, l.daily.lastRun)
	if err != nil {
		l.logf(domain.LogLevelWarn, "daily reconnect not scheduled: %v", err)
		return
	}
	l.daily.at = next
	l.arm(&l.daily.timer, next.Sub(now), (*loop).dailyReconnectDue)
}

func (l *loop) cancelDaily() {
	l.daily.timer.cancel()
	l.daily.profileID, l.daily.config = "", domain.DailyReconnect{}
}

// dailyReconnectDue restarts the tunnel when it is connected; otherwise
// the day is skipped. Either way the next day is scheduled.
func (l *loop) dailyReconnectDue() {
	if t := l.tunnel; l.status.State == domain.StateConnected && t != nil && !t.stopping {
		l.daily.lastRun = l.daily.at.Format(dayLayout)
		l.logf(domain.LogLevelInfo, reasonDailyReconnect)
		l.restart = true
		l.setState(domain.StateReconnecting, reasonDailyReconnect)
		l.reconcile()
	} else {
		l.logf(domain.LogLevelInfo, "scheduled daily reconnect skipped: the tunnel is not connected")
	}
	l.armDaily()
}

// setState changes the state. Leaving the connected state stops the public
// IP detection and forgets the public IP, which a reconnect may change;
// leaving the tunnel's states forgets what the tunnel reported.
func (l *loop) setState(state domain.ConnectionState, message string) {
	l.setStateSince(state, message, l.now())
}

// setStateSince is setState with the time the state began.
func (l *loop) setStateSince(state domain.ConnectionState, message string, since time.Time) {
	l.status.State, l.status.Message, l.status.Since = state, message, since
	l.status.MessageCode = ""
	if state != domain.StateConnected {
		l.publicIP.stop()
	}
	if state != domain.StateConnected && state != domain.StateReconnecting {
		l.status.VPNIP, l.status.Remote = "", ""
		l.status.DataCipher, l.status.ControlChannel = "", ""
	}
	l.broadcast(l.stateEvent())
	if state != domain.StateConnected {
		l.setPublicIP("")
	}
}

// stateEvent describes the current state.
func (l *loop) stateEvent() domain.StateEvent {
	event := domain.StateEvent{
		State: l.status.State, Message: l.status.Message, MessageCode: l.status.MessageCode,
		VPNIP: l.status.VPNIP, Remote: l.status.Remote, Since: l.status.Since,
	}
	if l.status.State == domain.StateError && l.status.LastError != nil {
		event.Code = l.status.LastError.Code
	}
	return event
}

func (l *loop) logf(level domain.LogLevel, format string, args ...any) {
	l.appendLog(domain.LogEvent{Time: l.now(), Level: level, Text: fmt.Sprintf(format, args...)})
}

func (l *loop) appendLog(e domain.LogEvent) {
	l.logs.add(e)
	l.broadcast(e)
}

func (l *loop) subscribe(events chan<- domain.Event) int {
	l.nextSubscriber++
	l.subscribers[l.nextSubscriber] = events
	return l.nextSubscriber
}

func (l *loop) unsubscribe(id int) {
	if events, ok := l.subscribers[id]; ok {
		close(events)
		delete(l.subscribers, id)
	}
}

// broadcast never blocks: a subscriber whose buffer is full is dropped.
func (l *loop) broadcast(e domain.Event) {
	for id, events := range l.subscribers {
		select {
		case events <- e:
		default:
			l.unsubscribe(id)
		}
	}
}

func (l *loop) now() time.Time { return l.cfg.Clock.Now().UTC() }
