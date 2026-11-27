package auth

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"tunneldeck/internal/domain"
)

func TestRememberedSessionTimeouts(t *testing.T) {
	const day = 24 * time.Hour
	tests := []struct {
		name     string
		remember bool
		steps    []time.Duration // clock advances, each followed by Authenticate
		wantLast bool            // result of the last Authenticate
	}{
		{"normal within idle timeout", false, []time.Duration{SessionIdleTimeout - time.Minute}, true},
		{"normal after idle timeout", false, []time.Duration{SessionIdleTimeout}, false},
		{"remembered after a normal idle timeout", true, []time.Duration{SessionIdleTimeout}, true},
		{"remembered within idle timeout", true, []time.Duration{RememberedIdleTimeout - time.Minute}, true},
		{"remembered after idle timeout", true, []time.Duration{RememberedIdleTimeout}, false},
		{"remembered used before the lifetime", true, []time.Duration{29 * day, 29 * day, 29 * day, 2*day + 23*time.Hour}, true},
		{"remembered used until the lifetime", true, []time.Duration{29 * day, 29 * day, 29 * day, 3 * day}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newSetUpService(t)
			token, err := ts.Login(testUsername, testPassword, testIP, ListenerLAN, tt.remember)
			if err != nil {
				t.Fatal(err)
			}
			var ok bool
			for i, step := range tt.steps {
				ts.clock.Advance(step)
				_, ok = ts.Authenticate(token)
				if i < len(tt.steps)-1 && !ok {
					t.Fatalf("session expired at step %d", i)
				}
			}
			if ok != tt.wantLast {
				t.Fatalf("Authenticate = %v, want %v", ok, tt.wantLast)
			}
		})
	}
}

func TestRememberedSessionsSurviveRestart(t *testing.T) {
	ts := newSetUpService(t)
	remembered := ts.mustRemember(t)
	normal := ts.mustLogin(t)
	records := ts.store.RememberedSessions()
	if len(records) != 1 {
		t.Fatalf("store holds %d sessions, want 1", len(records))
	}
	record := records[0]
	key := hashToken(remembered)
	want := domain.RememberedSession{
		TokenHash: hex.EncodeToString(key[:]), Username: testUsername,
		CreatedAt: ts.clock.Now(), LastUsedAt: ts.clock.Now(), ClientIP: testIP,
	}
	if record != want {
		t.Fatalf("stored = %+v, want %+v", record, want)
	}
	if strings.Contains(record.TokenHash, remembered) {
		t.Fatal("store holds the plain token")
	}

	ts.clock.Advance(time.Hour)
	restarted := ts.restart()
	if username, ok := restarted.Authenticate(remembered); !ok || username != testUsername {
		t.Fatalf("remembered session after restart = %q, %v", username, ok)
	}
	if _, ok := restarted.Authenticate(normal); ok {
		t.Fatal("normal session survived the restart")
	}
}

func TestRememberedLastUsedWritesAreThrottled(t *testing.T) {
	ts := newSetUpService(t)
	token := ts.mustRemember(t)
	if n := ts.store.writeCount(); n != 1 {
		t.Fatalf("%d writes after login, want 1", n)
	}
	for range 5 {
		ts.clock.Advance(10 * time.Minute)
		ts.Authenticate(token)
	}
	if n := ts.store.writeCount(); n != 1 {
		t.Fatalf("%d writes within an hour, want 1", n)
	}
	ts.clock.Advance(10 * time.Minute)
	ts.Authenticate(token)
	if n := ts.store.writeCount(); n != 2 {
		t.Fatalf("%d writes after an hour, want 2", n)
	}
	if got := ts.store.RememberedSessions()[0].LastUsedAt; !got.Equal(ts.clock.Now()) {
		t.Fatalf("stored last use = %v, want %v", got, ts.clock.Now())
	}
	ts.Authenticate(token)
	if n := ts.store.writeCount(); n != 2 {
		t.Fatalf("%d writes right after a write, want 2", n)
	}
}

func TestRememberedSessionCapDropsOldest(t *testing.T) {
	ts := newSetUpService(t)
	normal := ts.mustLogin(t)
	tokens := make([]string, 0, MaxRememberedSessions+1)
	for range MaxRememberedSessions + 1 {
		tokens = append(tokens, ts.mustRemember(t))
		ts.clock.Advance(time.Second)
	}
	if n := len(ts.store.RememberedSessions()); n != MaxRememberedSessions {
		t.Fatalf("store holds %d sessions, want %d", n, MaxRememberedSessions)
	}
	if _, ok := ts.Authenticate(tokens[0]); ok {
		t.Fatal("oldest remembered session survived the cap")
	}
	for _, token := range append(tokens[1:], normal) {
		if _, ok := ts.Authenticate(token); !ok {
			t.Fatal("a newer or a normal session was dropped")
		}
	}
}

func TestLogoutRemovesRememberedSession(t *testing.T) {
	ts := newSetUpService(t)
	token := ts.mustRemember(t)
	other := ts.mustRemember(t)
	if err := ts.Logout(token); err != nil {
		t.Fatal(err)
	}
	restarted := ts.restart()
	if _, ok := restarted.Authenticate(token); ok {
		t.Fatal("logged-out session is back after a restart")
	}
	if _, ok := restarted.Authenticate(other); !ok {
		t.Fatal("logout ended another remembered session")
	}
}

func TestLogoutStoreError(t *testing.T) {
	ts := newSetUpService(t)
	token := ts.mustRemember(t)
	ts.store.failWrites(errStoreFailed)
	if err := ts.Logout(token); !errors.Is(err, errStoreFailed) {
		t.Fatalf("Logout: err = %v, want %v", err, errStoreFailed)
	}
	if _, ok := ts.Authenticate(token); ok {
		t.Fatal("session valid after a logout with a store error")
	}
}

func TestLogoutEverywhere(t *testing.T) {
	ts := newSetUpService(t)
	tokens := []string{ts.mustLogin(t), ts.mustRemember(t), ts.mustRemember(t)}
	if err := ts.LogoutEverywhere(); err != nil {
		t.Fatal(err)
	}
	if n := len(ts.store.RememberedSessions()); n != 0 {
		t.Fatalf("store holds %d sessions, want 0", n)
	}
	restarted := ts.restart()
	for _, token := range tokens {
		if _, ok := ts.Authenticate(token); ok {
			t.Fatal("a session survived")
		}
		if _, ok := restarted.Authenticate(token); ok {
			t.Fatal("a session is back after a restart")
		}
	}
	ts.store.failWrites(errStoreFailed)
	if err := ts.LogoutEverywhere(); !errors.Is(err, errStoreFailed) {
		t.Fatalf("LogoutEverywhere: err = %v, want %v", err, errStoreFailed)
	}
}

func TestResetAdminRemovesRememberedSessions(t *testing.T) {
	ts := newSetUpService(t)
	token := ts.mustRemember(t)
	if err := ts.ResetAdmin(); err != nil {
		t.Fatal(err)
	}
	if n := len(ts.store.RememberedSessions()); n != 0 {
		t.Fatalf("store holds %d sessions after reset, want 0", n)
	}
	if err := ts.Setup(testUsername, testPassword); err != nil {
		t.Fatal(err)
	}
	if _, ok := ts.restart().Authenticate(token); ok {
		t.Fatal("remembered session valid after reset and new setup")
	}
}

func TestRememberLoginStoreError(t *testing.T) {
	ts := newSetUpService(t)
	ts.store.failWrites(errStoreFailed)
	if _, err := ts.Login(testUsername, testPassword, testIP, ListenerLAN, true); !errors.Is(err, errStoreFailed) {
		t.Fatalf("Login: err = %v, want %v", err, errStoreFailed)
	}
	if n := len(ts.sessions.sessions); n != 0 {
		t.Fatalf("%d sessions after a failed remember login, want 0", n)
	}
	ts.mustLogin(t)
}

func TestLoadSkipsUnusableRecords(t *testing.T) {
	clock := newFakeClock()
	now := clock.Now()
	valid := "valid-token"
	validKey := hashToken(valid)
	expiredKey := hashToken("expired-token")
	store := &fakeStore{
		account: &domain.AdminAccount{Username: testUsername, PasswordHash: "unused"},
		remembered: []domain.RememberedSession{
			{TokenHash: "not hex", Username: testUsername, CreatedAt: now, LastUsedAt: now},
			{TokenHash: "abcd", Username: testUsername, CreatedAt: now, LastUsedAt: now},
			{TokenHash: hex.EncodeToString(expiredKey[:]), Username: testUsername,
				CreatedAt: now.Add(-RememberedLifetime), LastUsedAt: now},
			{TokenHash: hex.EncodeToString(validKey[:]), Username: testUsername,
				CreatedAt: now.Add(-time.Hour), LastUsedAt: now.Add(-time.Hour), ClientIP: testIP},
		},
	}
	s := NewService(store, WithClock(clock.Now), WithHashParams(cheapParams))
	if n := len(s.sessions.sessions); n != 1 {
		t.Fatalf("%d sessions loaded, want 1", n)
	}
	if _, ok := s.Authenticate(valid); !ok {
		t.Fatal("valid remembered session not restored")
	}
	if n := store.writeCount(); n != 1 {
		t.Fatalf("%d writes, want 1 (the last-used update after an hour)", n)
	}
}

func TestLoadKeepsNewestWithinCap(t *testing.T) {
	clock := newFakeClock()
	store := &fakeStore{account: &domain.AdminAccount{Username: testUsername, PasswordHash: "unused"}}
	tokens := make([]string, 0, MaxRememberedSessions+2)
	for i := range MaxRememberedSessions + 2 {
		token := strings.Repeat("t", i+1)
		key := hashToken(token)
		created := clock.Now().Add(time.Duration(i) * time.Minute)
		store.remembered = append(store.remembered, domain.RememberedSession{
			TokenHash: hex.EncodeToString(key[:]), Username: testUsername, CreatedAt: created, LastUsedAt: created,
		})
		tokens = append(tokens, token)
	}
	clock.Advance(time.Hour)
	s := NewService(store, WithClock(clock.Now), WithHashParams(cheapParams))
	for i, token := range tokens {
		_, ok := s.Authenticate(token)
		if want := i >= 2; ok != want {
			t.Errorf("session %d valid = %v, want %v", i, ok, want)
		}
	}
}
