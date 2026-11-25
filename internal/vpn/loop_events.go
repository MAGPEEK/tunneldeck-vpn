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
	case domain.StateEvent:
		if !t.stopping {
			l.driverState(t, e)
		}
	}
}

func (l *loop) driverState(t *tunnel, e domain.StateEvent) {
	switch e.State {
	case domain.StateConnected:
		l.tunnelConnected(t, e)
	case domain.StateReconnecting:
		l.setState(domain.StateReconnecting, e.Message)
	case domain.StateDisconnected, domain.StateError:
		t.failure = endFailure(e)
		l.reconcile()
	}
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

// tunnelConnected routes replies through the tunnel on every connected
// event, because the VPN IP can change.
func (l *loop) tunnelConnected(t *tunnel, e domain.StateEvent) {
	if err := l.routeThroughTunnel(e.VPNIP); err != nil {
		t.failure = &failure{code: domain.ErrorCodeRoutingFailed, message: "routing through the tunnel failed: " + err.Error()}
		l.reconcile()
		return
	}
	l.failures = 0
	l.status.LastError = nil
	l.status.VPNIP, l.status.Remote = e.VPNIP, e.Remote
	l.setState(domain.StateConnected, "")
}

func (l *loop) installFirewall() error {
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	return l.cfg.Guard.InstallFirewall(ctx, l.cfg.HostAccess.HostAccessRules(), l.cfg.UIPort)
}

func (l *loop) routeThroughTunnel(vpnIP string) error {
	ip, err := netip.ParseAddr(vpnIP)
	if err != nil {
		return fmt.Errorf("the driver reported no valid VPN IP (%q)", vpnIP)
	}
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	return l.cfg.Guard.RouteThroughTunnel(ctx, ip)
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

func (l *loop) setState(state domain.ConnectionState, message string) {
	l.status.State, l.status.Message, l.status.Since = state, message, l.now()
	if state != domain.StateConnected && state != domain.StateReconnecting {
		l.status.VPNIP, l.status.Remote = "", ""
	}
	event := domain.StateEvent{
		State: state, Message: message, VPNIP: l.status.VPNIP, Remote: l.status.Remote, Since: l.status.Since,
	}
	if state == domain.StateError && l.status.LastError != nil {
		event.Code = l.status.LastError.Code
	}
	l.broadcast(event)
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
