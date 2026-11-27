package auth

import (
	"log/slog"
	"sync"
	"time"
)

// Login rate limit per client IP (SPEC §8): after failure n the client
// waits baseCooldown doubled n-1 times, at most maxCooldown. A record is
// forgotten clientForgetAfter after its last failure; that is longer than
// maxCooldown, so a forgotten record is never cooling down.
const (
	baseCooldown      = 10 * time.Second
	maxCooldown       = 15 * time.Minute
	clientForgetAfter = 30 * time.Minute
	maxTrackedClients = 10000
	purgeInterval     = time.Minute
)

// Login rate limit of the remote listener across all clients (SPEC §8.1):
// remoteMaxFailures failures within remoteWindow lock the listener for
// remoteBaseLock, doubled per earlier lock up to remoteMaxLock. The doubling
// resets remoteForgetAfter after the last remote failure.
const (
	remoteMaxFailures = 10
	remoteWindow      = 10 * time.Minute
	remoteBaseLock    = time.Minute
	remoteMaxLock     = 15 * time.Minute
	remoteForgetAfter = 30 * time.Minute
)

// Listener names the UI listener a login arrives on; it selects the limits
// that apply.
type Listener int

// Listeners.
const (
	// ListenerLAN is the plain-HTTP LAN listener: per-client cooldown only.
	ListenerLAN Listener = iota
	// ListenerRemote is the HTTPS remote-access listener (SPEC §8.1): the
	// per-client cooldown plus a lock for every client after too many
	// failures from any client.
	ListenerRemote
)

// loginLimiter enforces the login rate limits.
//
// An admitted attempt holds its client, and on the remote listener counts
// towards the remote limit, until it is reported as failed or succeeded,
// so parallel attempts cannot slip past the limits while a password is
// still being checked.
type loginLimiter struct {
	mu         sync.Mutex
	maxClients int
	clients    map[string]*clientRecord
	lastPurge  time.Time
	remote     remoteRecord
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		maxClients: maxTrackedClients,
		clients:    make(map[string]*clientRecord),
	}
}

// begin admits a login attempt by clientIP on listener or returns a
// *RateLimitError. An admitted attempt must be followed by failed or
// succeeded.
func (l *loginLimiter) begin(clientIP string, listener Listener, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.purgeStale(now, false)
	record := l.clients[clientIP]
	if record != nil && record.stale(now) {
		delete(l.clients, clientIP)
		record = nil
	}
	clientWait := record.wait(now)
	if listener == ListenerRemote {
		if remoteWait := l.remote.wait(now); remoteWait > 0 {
			return &RateLimitError{RetryAfter: max(remoteWait, clientWait), Remote: true}
		}
	}
	if clientWait > 0 {
		return &RateLimitError{RetryAfter: clientWait}
	}
	if record == nil {
		record = l.track(clientIP, now)
	}
	record.checking = true
	record.lastSeen = now
	if listener == ListenerRemote {
		l.remote.checking++
	}
	return nil
}

// failed ends an attempt admitted by begin with a failure: the client's
// cooldown starts and, on the remote listener, the failure counts towards
// the remote limit. It returns how long the client must wait before its
// next attempt.
func (l *loginLimiter) failed(clientIP string, listener Listener, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	record := l.clients[clientIP]
	if record == nil {
		record = l.track(clientIP, now)
	}
	cooldown := record.fail(now)
	slog.Warn("auth: login cooldown started", "client", clientIP, "failures", record.failures, "cooldown", cooldown.String())
	if listener != ListenerRemote {
		return cooldown
	}
	if lock, locked := l.remote.fail(now); locked {
		slog.Warn("auth: remote sign-in locked for all clients",
			"failures", remoteMaxFailures, "window", remoteWindow.String(), "lock", lock.String())
	}
	return max(cooldown, l.remote.wait(now))
}

// succeeded ends an attempt admitted by begin with a successful login,
// which clears the client's record.
func (l *loginLimiter) succeeded(clientIP string, listener Listener) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.clients, clientIP)
	if listener == ListenerRemote {
		l.remote.release()
	}
}

// track adds a record for clientIP, making room when the limit of tracked
// clients is reached. The caller holds l.mu.
func (l *loginLimiter) track(clientIP string, now time.Time) *clientRecord {
	if len(l.clients) >= l.maxClients {
		l.purgeStale(now, true)
	}
	if len(l.clients) >= l.maxClients {
		l.evictLeastRecent()
	}
	record := &clientRecord{}
	l.clients[clientIP] = record
	return record
}

// purgeStale removes forgotten records, at most once per purgeInterval
// unless forced. The caller holds l.mu.
func (l *loginLimiter) purgeStale(now time.Time, force bool) {
	if !force && now.Sub(l.lastPurge) < purgeInterval {
		return
	}
	l.lastPurge = now
	for clientIP, record := range l.clients {
		if record.stale(now) {
			delete(l.clients, clientIP)
		}
	}
}

// evictLeastRecent removes the record seen least recently. The caller
// holds l.mu.
func (l *loginLimiter) evictLeastRecent() {
	var victim string
	var oldest time.Time
	first := true
	for clientIP, record := range l.clients {
		if first || record.lastSeen.Before(oldest) {
			victim, oldest, first = clientIP, record.lastSeen, false
		}
	}
	delete(l.clients, victim)
}

// clientRecord is the login history of one client IP.
type clientRecord struct {
	failures      int
	cooldownUntil time.Time
	// lastSeen is the start of the last admitted attempt or the last
	// failure, whichever is later.
	lastSeen time.Time
	// checking is true while an admitted attempt is being checked.
	checking bool
}

// wait returns how long the client must wait before its next attempt; a
// nil record never waits. While an attempt is being checked, further
// attempts wait for the cooldown that follows if it fails.
func (r *clientRecord) wait(now time.Time) time.Duration {
	switch {
	case r == nil:
		return 0
	case r.checking:
		return clientCooldown(r.failures + 1)
	case now.Before(r.cooldownUntil):
		return r.cooldownUntil.Sub(now)
	}
	return 0
}

// fail records a failed attempt and returns the cooldown it starts.
func (r *clientRecord) fail(now time.Time) time.Duration {
	r.checking = false
	r.failures++
	r.lastSeen = now
	cooldown := clientCooldown(r.failures)
	r.cooldownUntil = now.Add(cooldown)
	return cooldown
}

// stale reports whether the record can be forgotten.
func (r *clientRecord) stale(now time.Time) bool {
	return !r.checking && now.Sub(r.lastSeen) >= clientForgetAfter
}

// remoteRecord is the login history of the remote listener across all
// clients.
type remoteRecord struct {
	// failures holds the times of the failures within remoteWindow since
	// the last lock.
	failures    []time.Time
	lastFailure time.Time
	locks       int
	lockedUntil time.Time
	// checking counts the admitted attempts being checked.
	checking int
}

// wait returns how long the remote listener rejects every login. While
// attempts being checked could complete the failures that start a lock,
// further attempts wait for that lock.
func (r *remoteRecord) wait(now time.Time) time.Duration {
	r.expire(now)
	switch {
	case now.Before(r.lockedUntil):
		return r.lockedUntil.Sub(now)
	case len(r.failures)+r.checking >= remoteMaxFailures:
		return remoteLock(r.locks)
	}
	return 0
}

// fail records a failed attempt and reports the lock it starts, if any.
func (r *remoteRecord) fail(now time.Time) (time.Duration, bool) {
	r.release()
	r.expire(now)
	r.failures = append(r.failures, now)
	r.lastFailure = now
	if len(r.failures) < remoteMaxFailures {
		return 0, false
	}
	lock := remoteLock(r.locks)
	r.lockedUntil = now.Add(lock)
	r.locks++
	r.failures = nil
	return lock, true
}

// release ends an attempt being checked.
func (r *remoteRecord) release() {
	r.checking = max(0, r.checking-1)
}

// expire drops failures older than remoteWindow and resets the lock
// doubling remoteForgetAfter after the last failure.
func (r *remoteRecord) expire(now time.Time) {
	for len(r.failures) > 0 && now.Sub(r.failures[0]) >= remoteWindow {
		r.failures = r.failures[1:]
	}
	if now.Sub(r.lastFailure) >= remoteForgetAfter {
		r.locks = 0
	}
}

// clientCooldown returns the cooldown after failure n of a client:
// baseCooldown doubled n-1 times, capped at maxCooldown.
func clientCooldown(n int) time.Duration {
	return doubled(baseCooldown, maxCooldown, n-1)
}

// remoteLock returns the remote lock after previous earlier locks:
// remoteBaseLock doubled per previous lock, capped at remoteMaxLock.
func remoteLock(previous int) time.Duration {
	return doubled(remoteBaseLock, remoteMaxLock, previous)
}

// doubled returns base doubled times times, capped at limit.
func doubled(base, limit time.Duration, times int) time.Duration {
	d := base
	for range times {
		d *= 2
		if d >= limit {
			return limit
		}
	}
	return d
}
