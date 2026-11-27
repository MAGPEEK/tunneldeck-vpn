package auth

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// failLogin makes a failed login from clientIP on listener and fails the
// test if it is rate limited.
func (ts *testService) failLogin(t *testing.T, clientIP string, listener Listener) {
	t.Helper()
	if _, err := ts.Login(testUsername, "wrong password!", clientIP, listener, false); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("failed login from %s: err = %v, want ErrInvalidCredentials", clientIP, err)
	}
}

// failRemoteLogins makes n failed logins on the remote listener, each from
// another client, starting at 198.51.100.<first>.
func (ts *testService) failRemoteLogins(t *testing.T, first, n int) {
	t.Helper()
	for i := range n {
		ts.failLogin(t, fmt.Sprintf("198.51.100.%d", first+i), ListenerRemote)
	}
}

// requireRateLimited checks that a login with the right password from
// clientIP on listener is rejected for exactly want, without computing a
// hash, and whether the remote listener is locked for everyone.
func (ts *testService) requireRateLimited(t *testing.T, clientIP string, listener Listener, want time.Duration, remote bool) {
	t.Helper()
	calls := ts.deriver.calls.Load()
	_, err := ts.Login(testUsername, testPassword, clientIP, listener, false)
	var limited *RateLimitError
	if !errors.As(err, &limited) || !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Login: err = %v, want *RateLimitError", err)
	}
	if limited.RetryAfter != want || limited.Remote != remote {
		t.Fatalf("RetryAfter = %s, Remote = %v; want %s, %v", limited.RetryAfter, limited.Remote, want, remote)
	}
	if ts.deriver.calls.Load() != calls {
		t.Fatal("rate-limited login computed a hash")
	}
}

// requireLogin checks that a login with the right password from clientIP
// on listener succeeds.
func (ts *testService) requireLogin(t *testing.T, clientIP string, listener Listener) {
	t.Helper()
	if _, err := ts.Login(testUsername, testPassword, clientIP, listener, false); err != nil {
		t.Fatalf("login from %s: %v", clientIP, err)
	}
}

func TestClientCooldown(t *testing.T) {
	tests := []struct {
		failures int
		want     time.Duration
	}{
		{1, 10 * time.Second},
		{2, 20 * time.Second},
		{3, 40 * time.Second},
		{4, 80 * time.Second},
		{5, 160 * time.Second},
		{6, 320 * time.Second},
		{7, 640 * time.Second},
		{8, 15 * time.Minute},
		{100, 15 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprint(tt.failures), func(t *testing.T) {
			if got := clientCooldown(tt.failures); got != tt.want {
				t.Fatalf("clientCooldown(%d) = %s, want %s", tt.failures, got, tt.want)
			}
		})
	}
}

func TestRemoteLock(t *testing.T) {
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
			if got := remoteLock(tt.previous); got != tt.want {
				t.Fatalf("remoteLock(%d) = %s, want %s", tt.previous, got, tt.want)
			}
		})
	}
}

func TestRateLimitCooldownGrowsFromTheFirstFailure(t *testing.T) {
	for _, listener := range []Listener{ListenerLAN, ListenerRemote} {
		t.Run(fmt.Sprint(listener), func(t *testing.T) {
			ts := newSetUpService(t)
			for _, want := range []time.Duration{
				10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second, 160 * time.Second,
				320 * time.Second, 640 * time.Second, 15 * time.Minute, 15 * time.Minute,
			} {
				ts.failLogin(t, testIP, listener)
				ts.requireRateLimited(t, testIP, listener, want, false)
				ts.clock.Advance(want)
			}
			ts.requireLogin(t, testIP, listener)
		})
	}
}

func TestFailedLoginReportsTheWaitItStarts(t *testing.T) {
	ts := newSetUpService(t)
	requireWait := func(clientIP string, listener Listener, want time.Duration) {
		t.Helper()
		_, err := ts.Login(testUsername, "wrong password!", clientIP, listener, false)
		var failed *CredentialsError
		if !errors.As(err, &failed) || !errors.Is(err, ErrInvalidCredentials) || failed.RetryAfter != want {
			t.Fatalf("Login from %s: err = %v, want *CredentialsError with a wait of %s", clientIP, err, want)
		}
	}
	requireWait(testIP, ListenerLAN, 10*time.Second)
	ts.clock.Advance(10 * time.Second)
	requireWait(testIP, ListenerLAN, 20*time.Second)
	ts.failRemoteLogins(t, 0, remoteMaxFailures-1)
	requireWait("203.0.113.1", ListenerRemote, time.Minute)
}

func TestRateLimitRejectionsDoNotExtendTheCooldown(t *testing.T) {
	ts := newSetUpService(t)
	ts.failLogin(t, testIP, ListenerLAN)
	ts.clock.Advance(4 * time.Second)
	for range 3 {
		ts.requireRateLimited(t, testIP, ListenerLAN, 6*time.Second, false)
	}
	ts.clock.Advance(6 * time.Second)
	ts.failLogin(t, testIP, ListenerLAN)
	ts.requireRateLimited(t, testIP, ListenerLAN, 20*time.Second, false)
}

func TestRateLimitSuccessClearsRecord(t *testing.T) {
	ts := newSetUpService(t)
	for _, wait := range []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second} {
		ts.failLogin(t, testIP, ListenerLAN)
		ts.clock.Advance(wait)
	}
	ts.mustLogin(t)
	ts.failLogin(t, testIP, ListenerLAN)
	ts.requireRateLimited(t, testIP, ListenerLAN, 10*time.Second, false)
}

func TestRateLimitForgetsAfterQuietPeriod(t *testing.T) {
	tests := []struct {
		name  string
		quiet time.Duration
		want  time.Duration
	}{
		{name: "still remembered", quiet: clientForgetAfter - time.Second, want: 20 * time.Second},
		{name: "forgotten", quiet: clientForgetAfter, want: 10 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newSetUpService(t)
			ts.failLogin(t, testIP, ListenerLAN)
			ts.clock.Advance(tt.quiet)
			ts.failLogin(t, testIP, ListenerLAN)
			ts.requireRateLimited(t, testIP, ListenerLAN, tt.want, false)
		})
	}
}

func TestRateLimitIsPerClientIP(t *testing.T) {
	ts := newSetUpService(t)
	ts.failLogin(t, "192.0.2.1", ListenerLAN)
	ts.requireRateLimited(t, "192.0.2.1", ListenerLAN, 10*time.Second, false)
	ts.requireLogin(t, "192.0.2.2", ListenerLAN)
}

func TestRateLimitClientRecordSpansBothListeners(t *testing.T) {
	ts := newSetUpService(t)
	ts.failLogin(t, testIP, ListenerLAN)
	ts.requireRateLimited(t, testIP, ListenerRemote, 10*time.Second, false)
}

func TestRateLimitPurgesStaleRecords(t *testing.T) {
	ts := newSetUpService(t)
	for i := range 20 {
		ts.failLogin(t, fmt.Sprintf("198.51.100.%d", i), ListenerLAN)
	}
	ts.clock.Advance(clientForgetAfter)
	ts.failLogin(t, testIP, ListenerLAN)
	if n := len(ts.limiter.clients); n != 1 {
		t.Fatalf("%d records after purge, want 1", n)
	}
}

func TestRateLimitBoundsTrackedClients(t *testing.T) {
	ts := newSetUpService(t)
	ts.limiter.maxClients = 3
	for i := range 10 {
		ts.failLogin(t, fmt.Sprintf("198.51.100.%d", i), ListenerLAN)
		ts.clock.Advance(time.Second)
	}
	if n := len(ts.limiter.clients); n != 3 {
		t.Fatalf("%d records, want 3", n)
	}
	if _, ok := ts.limiter.clients["198.51.100.9"]; !ok {
		t.Fatal("newest client evicted")
	}
	if _, ok := ts.limiter.clients["198.51.100.0"]; ok {
		t.Fatal("least recent client kept")
	}
}

func TestRateLimitAdmitsOneAttemptPerClientAtATime(t *testing.T) {
	limiter := newLoginLimiter()
	now := newFakeClock().Now()
	if err := limiter.begin(testIP, ListenerLAN, now); err != nil {
		t.Fatalf("first attempt: %v", err)
	}
	var limited *RateLimitError
	if err := limiter.begin(testIP, ListenerLAN, now); !errors.As(err, &limited) || limited.RetryAfter != 10*time.Second {
		t.Fatalf("attempt while one is checked: err = %v, want a wait of 10s", err)
	}
	limiter.succeeded(testIP, ListenerLAN)
	if err := limiter.begin(testIP, ListenerLAN, now); err != nil {
		t.Fatalf("attempt after a success: %v", err)
	}
	limiter.failed(testIP, ListenerLAN, now)
	if err := limiter.begin(testIP, ListenerLAN, now); !errors.As(err, &limited) || limited.RetryAfter != 10*time.Second {
		t.Fatalf("attempt after a failure: err = %v, want a wait of 10s", err)
	}
	if n := limiter.clients[testIP].failures; n != 1 {
		t.Fatalf("%d failures counted, want 1: rejected attempts must not count", n)
	}
}

func TestRateLimitHoldsUnderParallelLogins(t *testing.T) {
	tests := []struct {
		name        string
		listener    Listener
		clientIP    func(i int) string
		wantChecked int
		wantRemote  bool
		wantWait    time.Duration
	}{
		{
			name: "one client", listener: ListenerLAN, clientIP: func(int) string { return testIP },
			wantChecked: 1, wantWait: 10 * time.Second,
		},
		{
			name: "many clients on the remote listener", listener: ListenerRemote,
			clientIP:    func(i int) string { return fmt.Sprintf("198.51.100.%d", i) },
			wantChecked: remoteMaxFailures, wantRemote: true, wantWait: time.Minute,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newSetUpService(t)
			const attempts = 30
			var (
				wg       sync.WaitGroup
				mu       sync.Mutex
				checked  int
				rejected []*RateLimitError
			)
			for i := range attempts {
				wg.Go(func() {
					_, err := ts.Login(testUsername, "wrong password!", tt.clientIP(i), tt.listener, false)
					mu.Lock()
					defer mu.Unlock()
					var limited *RateLimitError
					switch {
					case errors.Is(err, ErrInvalidCredentials):
						checked++
					case errors.As(err, &limited):
						rejected = append(rejected, limited)
					default:
						t.Errorf("attempt %d: err = %v", i, err)
					}
				})
			}
			wg.Wait()
			if checked != tt.wantChecked {
				t.Fatalf("%d parallel attempts were checked, want %d", checked, tt.wantChecked)
			}
			for _, limited := range rejected {
				if limited.Remote != tt.wantRemote || limited.RetryAfter != tt.wantWait {
					t.Fatalf("rejection = %+v, want Remote %v and a wait of %s", limited, tt.wantRemote, tt.wantWait)
				}
			}
		})
	}
}

func TestRemoteLockAfterTenFailuresFromAnyClients(t *testing.T) {
	ts := newSetUpService(t)
	ts.failRemoteLogins(t, 0, remoteMaxFailures-1)
	ts.requireLogin(t, "203.0.113.1", ListenerRemote)
	ts.failRemoteLogins(t, remoteMaxFailures, 1)
	ts.requireRateLimited(t, "203.0.113.2", ListenerRemote, time.Minute, true)
	ts.requireLogin(t, "203.0.113.2", ListenerLAN)
	ts.clock.Advance(time.Minute)
	ts.requireLogin(t, "203.0.113.2", ListenerRemote)
}

func TestRemoteLockReportsTheLongerWait(t *testing.T) {
	ts := newSetUpService(t)
	for _, wait := range []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second} {
		ts.failLogin(t, testIP, ListenerRemote)
		ts.clock.Advance(wait)
	}
	ts.failLogin(t, testIP, ListenerRemote)
	ts.failRemoteLogins(t, 0, remoteMaxFailures-5)
	ts.requireRateLimited(t, "203.0.113.1", ListenerRemote, time.Minute, true)
	ts.requireRateLimited(t, testIP, ListenerRemote, 160*time.Second, true)
	ts.requireRateLimited(t, testIP, ListenerLAN, 160*time.Second, false)
}

func TestRemoteLockCountsFailuresWithinTheWindow(t *testing.T) {
	ts := newSetUpService(t)
	ts.failRemoteLogins(t, 0, remoteMaxFailures-1)
	ts.clock.Advance(remoteWindow)
	ts.failRemoteLogins(t, 100, remoteMaxFailures-1)
	ts.requireLogin(t, "203.0.113.1", ListenerRemote)
	ts.failRemoteLogins(t, 200, 1)
	ts.requireRateLimited(t, "203.0.113.1", ListenerRemote, time.Minute, true)
}

func TestRemoteLockIgnoresLANFailures(t *testing.T) {
	ts := newSetUpService(t)
	for i := range 2 * remoteMaxFailures {
		ts.failLogin(t, fmt.Sprintf("198.51.100.%d", i), ListenerLAN)
	}
	ts.requireLogin(t, "203.0.113.1", ListenerRemote)
}

func TestRemoteLockDoublesAndResetsAfterQuietPeriod(t *testing.T) {
	ts := newSetUpService(t)
	for i, want := range []time.Duration{
		time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 15 * time.Minute, 15 * time.Minute,
	} {
		ts.failRemoteLogins(t, i*remoteMaxFailures, remoteMaxFailures)
		ts.requireRateLimited(t, "203.0.113.1", ListenerRemote, want, true)
		ts.clock.Advance(want)
	}
	ts.clock.Advance(remoteForgetAfter)
	ts.failRemoteLogins(t, 0, remoteMaxFailures)
	ts.requireRateLimited(t, "203.0.113.1", ListenerRemote, time.Minute, true)
}

func TestRateLimitLogsCooldownsWithoutCredentials(t *testing.T) {
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	ts := newSetUpService(t)
	ts.failLogin(t, testIP, ListenerLAN)
	ts.failRemoteLogins(t, 0, remoteMaxFailures)
	logged := buf.String()
	for _, want := range []string{
		`level=WARN msg="auth: login cooldown started" client=` + testIP + ` failures=1 cooldown=10s`,
		`level=WARN msg="auth: remote sign-in locked for all clients" failures=10 window=10m0s lock=1m0s`,
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("log lacks %q:\n%s", want, logged)
		}
	}
	for _, secret := range []string{"wrong password!", testUsername} {
		if strings.Contains(logged, secret) {
			t.Errorf("log contains %q:\n%s", secret, logged)
		}
	}
}

func TestRateLimitErrorMessage(t *testing.T) {
	tests := []struct {
		err  *RateLimitError
		want string
	}{
		{&RateLimitError{RetryAfter: 90 * time.Second}, "too many failed logins, retry after 1m30s"},
		{&RateLimitError{RetryAfter: time.Minute, Remote: true}, "too many failed logins on the remote listener, retry after 1m0s"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			err := error(tt.err)
			if got := err.Error(); got != tt.want {
				t.Fatalf("Error() = %q, want %q", got, tt.want)
			}
			if !errors.Is(err, ErrRateLimited) || errors.Is(err, ErrInvalidCredentials) {
				t.Fatal("rate-limit error matches the wrong sentinel")
			}
		})
	}
}
