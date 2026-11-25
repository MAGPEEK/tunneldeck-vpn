package auth

import (
	"sync"
	"time"
)

// Login rate limit (SPEC §8, §8.1): maxFailures failed logins per client
// within failureWindow lock the client out, strictMaxFailures for clients
// under LoginLimitStrict. Each further lockout doubles, from baseLockout up to
// maxLockout. A client's record is forgotten after forgetAfter without
// failures, which also resets the backoff; it is longer than maxLockout so a
// client that keeps failing stays at the cap.
const (
	maxFailures       = 5
	strictMaxFailures = 3
	failureWindow     = time.Minute
	baseLockout       = time.Minute
	maxLockout        = 15 * time.Minute
	forgetAfter       = 2 * maxLockout
	maxTrackedClients = 10000
)

// LoginLimit selects how many failed logins a client may make per minute.
type LoginLimit int

// Login limits.
const (
	// LoginLimitStandard allows 5 failures per minute.
	LoginLimitStandard LoginLimit = iota
	// LoginLimitStrict allows 3 failures per minute; it is meant for clients
	// reaching the UI from outside the local network.
	LoginLimitStrict
)

// maxFailures returns the failures that start a lockout under l.
func (l LoginLimit) maxFailures() int {
	if l == LoginLimitStrict {
		return strictMaxFailures
	}
	return maxFailures
}

type clientRecord struct {
	windowStart time.Time
	failures    int
	lockouts    int
	lockedUntil time.Time
	lastFailure time.Time
}

// loginLimiter counts login attempts per client IP.
//
// An attempt counts as a failure when it starts and is cleared when it
// succeeds, so parallel attempts cannot slip past the limit while their
// passwords are still being checked.
type loginLimiter struct {
	mu         sync.Mutex
	maxClients int
	records    map[string]*clientRecord
	lastPurge  time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		maxClients: maxTrackedClients,
		records:    make(map[string]*clientRecord),
	}
}

// begin registers a login attempt by clientIP under limit. It returns false
// and the remaining lockout when the client is locked out.
func (l *loginLimiter) begin(clientIP string, limit LoginLimit, now time.Time) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.purgeStale(now, false)
	record, ok := l.records[clientIP]
	if ok && record.stale(now) {
		delete(l.records, clientIP)
		ok = false
	}
	if ok && now.Before(record.lockedUntil) {
		return record.lockedUntil.Sub(now), false
	}
	if !ok {
		record = l.track(clientIP, now)
	}
	record.countFailure(limit.maxFailures(), now)
	return 0, true
}

// succeeded clears the record of clientIP after a successful login.
func (l *loginLimiter) succeeded(clientIP string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.records, clientIP)
}

// track adds a record for clientIP, making room when the limit of tracked
// clients is reached. The caller holds l.mu.
func (l *loginLimiter) track(clientIP string, now time.Time) *clientRecord {
	if len(l.records) >= l.maxClients {
		l.purgeStale(now, true)
	}
	if len(l.records) >= l.maxClients {
		l.evictLeastRecent()
	}
	record := &clientRecord{}
	l.records[clientIP] = record
	return record
}

// purgeStale removes forgotten records, at most once per failureWindow
// unless forced. The caller holds l.mu.
func (l *loginLimiter) purgeStale(now time.Time, force bool) {
	if !force && now.Sub(l.lastPurge) < failureWindow {
		return
	}
	l.lastPurge = now
	for clientIP, record := range l.records {
		if record.stale(now) {
			delete(l.records, clientIP)
		}
	}
}

// evictLeastRecent removes the record with the oldest failure. The caller
// holds l.mu.
func (l *loginLimiter) evictLeastRecent() {
	var victim string
	var oldest time.Time
	first := true
	for clientIP, record := range l.records {
		if first || record.lastFailure.Before(oldest) {
			victim, oldest, first = clientIP, record.lastFailure, false
		}
	}
	delete(l.records, victim)
}

// countFailure records a failed attempt and starts a lockout when the
// window holds limit failures.
func (r *clientRecord) countFailure(limit int, now time.Time) {
	if now.Sub(r.windowStart) >= failureWindow {
		r.windowStart = now
		r.failures = 0
	}
	r.failures++
	r.lastFailure = now
	if r.failures >= limit {
		r.lockedUntil = now.Add(lockoutDuration(r.lockouts))
		r.lockouts++
		r.failures = 0
	}
}

// stale reports whether the record can be forgotten. A lockout never
// outlasts maxLockout after the last failure, so a stale record is never
// locked.
func (r *clientRecord) stale(now time.Time) bool {
	return now.Sub(r.lastFailure) >= forgetAfter
}

// lockoutDuration returns the lockout after previous earlier lockouts:
// baseLockout doubled per previous lockout, capped at maxLockout.
func lockoutDuration(previous int) time.Duration {
	lockout := baseLockout
	for range previous {
		lockout *= 2
		if lockout >= maxLockout {
			return maxLockout
		}
	}
	return lockout
}
