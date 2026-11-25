package auth

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/store"
)

var _ AccountStore = (*store.Store)(nil)

// cheapParams keep tests fast; production uses DefaultHashParams.
var cheapParams = HashParams{MemoryKiB: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}

const (
	testUsername = "admin"
	testPassword = "correct horse battery"
	testIP       = "192.0.2.10"
)

var errStoreFailed = errors.New("store failed")

type fakeStore struct {
	mu        sync.Mutex
	account   *domain.AdminAccount
	createErr error
	removeErr error
}

func (f *fakeStore) AdminAccount() (domain.AdminAccount, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.account == nil {
		return domain.AdminAccount{}, false
	}
	return *f.account, true
}

func (f *fakeStore) CreateAdminAccount(account domain.AdminAccount) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return f.createErr
	}
	if f.account != nil {
		return domain.ErrSetupAlreadyDone
	}
	f.account = &account
	return nil
}

func (f *fakeStore) RemoveAdminAccount() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.removeErr != nil {
		return f.removeErr
	}
	f.account = nil
	return nil
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// countingDeriver wraps the real key derivation and counts its calls.
type countingDeriver struct {
	calls atomic.Int64
	next  keyDeriver
}

func (d *countingDeriver) derive(password, salt []byte, iterations, memoryKiB uint32, parallelism uint8, keyLength uint32) []byte {
	d.calls.Add(1)
	return d.next(password, salt, iterations, memoryKiB, parallelism, keyLength)
}

type testService struct {
	*Service
	store   *fakeStore
	clock   *fakeClock
	deriver *countingDeriver
}

func newTestService(t *testing.T) *testService {
	t.Helper()
	ts := &testService{store: &fakeStore{}, clock: newFakeClock()}
	ts.Service = NewService(ts.store, WithClock(ts.clock.Now), WithHashParams(cheapParams))
	ts.deriver = &countingDeriver{next: ts.hasher.derive}
	ts.hasher.derive = ts.deriver.derive
	return ts
}

// newSetUpService returns a service with the test admin account.
func newSetUpService(t *testing.T) *testService {
	t.Helper()
	ts := newTestService(t)
	if err := ts.Setup(testUsername, testPassword); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	return ts
}

func (ts *testService) mustLogin(t *testing.T) string {
	t.Helper()
	token, err := ts.Login(testUsername, testPassword, testIP, LoginLimitStandard)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	return token
}
