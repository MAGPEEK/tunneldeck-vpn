package auth

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// failLogins makes n failed logins from clientIP and fails the test if any
// of them is rate limited.
func (ts *testService) failLogins(t *testing.T, clientIP string, n int) {
	t.Helper()
	for i := range n {
		if _, err := ts.Login(testUsername, "wrong password!", clientIP, LoginLimitStandard); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("failed login %d: err = %v, want ErrInvalidCredentials", i+1, err)
		}
	}
}

// requireLockedOut checks that clientIP is locked out for exactly want.
func (ts *testService) requireLockedOut(t *testing.T, clientIP string, want time.Duration) {
	t.Helper()
	calls := ts.deriver.calls.Load()
	_, err := ts.Login(testUsername, testPassword, clientIP, LoginLimitStandard)
	var limited *RateLimitError
	if !errors.As(err, &limited) || !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Login: err = %v, want *RateLimitError", err)
	}
	if limited.RetryAfter != want {
		t.Fatalf("RetryAfter = %s, want %s", limited.RetryAfter, want)
	}
	if ts.deriver.calls.Load() != calls {
		t.Fatal("rate-limited login computed a hash")
	}
}

func TestRateLimitLocksAfterFiveFailures(t *testing.T) {
	ts := newSetUpService(t)
	ts.failLogins(t, testIP, maxFailures)
	ts.requireLockedOut(t, testIP, time.Minute)
	ts.clock.Advance(20 * time.Second)
	ts.requireLockedOut(t, testIP, 40*time.Second)
	ts.clock.Advance(40 * time.Second)
	ts.mustLogin(t)
}

func TestRateLimitPerLoginLimit(t *testing.T) {
	tests := []struct {
		name         string
		limit        LoginLimit
		failuresLeft int
	}{
		{name: "standard", limit: LoginLimitStandard, failuresLeft: 5},
		{name: "strict", limit: LoginLimitStrict, failuresLeft: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newSetUpService(t)
			for i := range tt.failuresLeft {
				if _, err := ts.Login(testUsername, "wrong password!", testIP, tt.limit); !errors.Is(err, ErrInvalidCredentials) {
					t.Fatalf("failure %d: err = %v, want ErrInvalidCredentials", i+1, err)
				}
			}
			_, err := ts.Login(testUsername, testPassword, testIP, tt.limit)
			var limited *RateLimitError
			if !errors.As(err, &limited) || limited.RetryAfter != time.Minute {
				t.Fatalf("after %d failures: err = %v, want a one-minute lockout", tt.failuresLeft, err)
			}
		})
	}
}

func TestRateLimitCountsFailuresPerWindow(t *testing.T) {
	ts := newSetUpService(t)
	ts.failLogins(t, testIP, maxFailures-1)
	ts.clock.Advance(failureWindow)
	ts.failLogins(t, testIP, maxFailures-1)
	ts.mustLogin(t)
}

func TestRateLimitIsPerClientIP(t *testing.T) {
	ts := newSetUpService(t)
	ts.failLogins(t, "192.0.2.1", maxFailures)
	ts.requireLockedOut(t, "192.0.2.1", time.Minute)
	if _, err := ts.Login(testUsername, testPassword, "192.0.2.2", LoginLimitStandard); err != nil {
		t.Fatalf("login from another IP: %v", err)
	}
}

func TestRateLimitBackoffDoublesUpToCap(t *testing.T) {
	ts := newSetUpService(t)
	for _, want := range []time.Duration{
		time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 15 * time.Minute, 15 * time.Minute,
	} {
		ts.failLogins(t, testIP, maxFailures)
		ts.requireLockedOut(t, testIP, want)
		ts.clock.Advance(want)
	}
}

func TestRateLimitSuccessClearsRecord(t *testing.T) {
	ts := newSetUpService(t)
	ts.failLogins(t, testIP, maxFailures)
	ts.clock.Advance(time.Minute)
	ts.mustLogin(t)
	ts.failLogins(t, testIP, maxFailures)
	ts.requireLockedOut(t, testIP, time.Minute)
}

func TestRateLimitBackoffResetsAfterQuietPeriod(t *testing.T) {
	ts := newSetUpService(t)
	ts.failLogins(t, testIP, maxFailures)
	ts.clock.Advance(time.Minute)
	ts.failLogins(t, testIP, maxFailures)
	ts.requireLockedOut(t, testIP, 2*time.Minute)
	ts.clock.Advance(forgetAfter)
	ts.failLogins(t, testIP, maxFailures)
	ts.requireLockedOut(t, testIP, time.Minute)
}

func TestRateLimitPurgesStaleRecords(t *testing.T) {
	ts := newSetUpService(t)
	for i := range 20 {
		ts.failLogins(t, fmt.Sprintf("198.51.100.%d", i), 1)
	}
	ts.clock.Advance(forgetAfter)
	ts.failLogins(t, testIP, 1)
	if n := len(ts.limiter.records); n != 1 {
		t.Fatalf("%d records after purge, want 1", n)
	}
}

func TestRateLimitBoundsTrackedClients(t *testing.T) {
	ts := newSetUpService(t)
	ts.limiter.maxClients = 3
	for i := range 10 {
		ts.failLogins(t, fmt.Sprintf("198.51.100.%d", i), 1)
		ts.clock.Advance(time.Second)
	}
	if n := len(ts.limiter.records); n != 3 {
		t.Fatalf("%d records, want 3", n)
	}
	if _, ok := ts.limiter.records["198.51.100.9"]; !ok {
		t.Fatal("newest client evicted")
	}
	if _, ok := ts.limiter.records["198.51.100.0"]; ok {
		t.Fatal("least recent client kept")
	}
}

func TestRateLimitHoldsUnderParallelLogins(t *testing.T) {
	ts := newSetUpService(t)
	const attempts = 20
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		checked int
	)
	for range attempts {
		wg.Go(func() {
			_, err := ts.Login(testUsername, "wrong password!", testIP, LoginLimitStandard)
			if errors.Is(err, ErrInvalidCredentials) {
				mu.Lock()
				checked++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if checked != maxFailures {
		t.Fatalf("%d parallel attempts were checked, want %d", checked, maxFailures)
	}
}

func TestLockoutDuration(t *testing.T) {
	tests := []struct {
		previous int
		want     time.Duration
	}{
		{0, time.Minute},
		{1, 2 * time.Minute},
		{2, 4 * time.Minute},
		{3, 8 * time.Minute},
		{4, 15 * time.Minute},
		{100, 15 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprint(tt.previous), func(t *testing.T) {
			if got := lockoutDuration(tt.previous); got != tt.want {
				t.Fatalf("lockoutDuration(%d) = %s, want %s", tt.previous, got, tt.want)
			}
		})
	}
}

func TestRateLimitErrorMessage(t *testing.T) {
	err := error(&RateLimitError{RetryAfter: 90 * time.Second})
	if got, want := err.Error(), "too many failed logins, retry after 1m30s"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("rate-limit error matches ErrInvalidCredentials")
	}
}
