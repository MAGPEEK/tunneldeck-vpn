package auth

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"tunneldeck/internal/domain"
)

func TestSetupRequired(t *testing.T) {
	ts := newTestService(t)
	if !ts.SetupRequired() {
		t.Fatal("SetupRequired = false before setup")
	}
	if err := ts.Setup(testUsername, testPassword); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if ts.SetupRequired() {
		t.Fatal("SetupRequired = true after setup")
	}
}

func TestSetupStoresArgon2idHash(t *testing.T) {
	ts := newSetUpService(t)
	account, _ := ts.store.AdminAccount()
	if account.Username != testUsername {
		t.Fatalf("username = %q, want %q", account.Username, testUsername)
	}
	stored, err := parsePasswordHash(account.PasswordHash)
	if err != nil {
		t.Fatalf("stored hash: %v", err)
	}
	if stored.params != cheapParams {
		t.Fatalf("stored params = %+v, want %+v", stored.params, cheapParams)
	}
	if !ts.hasher.matches(stored, testPassword) {
		t.Fatal("stored hash does not match the password")
	}
}

func TestSetupValidation(t *testing.T) {
	tests := []struct {
		name       string
		username   string
		password   string
		wantFields []string
	}{
		{"valid", "admin", testPassword, nil},
		{"username 3 chars", "abc", testPassword, nil},
		{"username 32 chars", strings.Repeat("a", 32), testPassword, nil},
		{"username all allowed chars", "A-z_0.9", testPassword, nil},
		{"password 12 chars", "admin", strings.Repeat("p", 12), nil},
		{"password 256 chars", "admin", strings.Repeat("p", 256), nil},
		{"password 12 multibyte chars", "admin", strings.Repeat("ä", 12), nil},
		{"username 2 chars", "ab", testPassword, []string{"username"}},
		{"username 33 chars", strings.Repeat("a", 33), testPassword, []string{"username"}},
		{"username empty", "", testPassword, []string{"username"}},
		{"username with space", "ad min", testPassword, []string{"username"}},
		{"username with umlaut", "jörg", testPassword, []string{"username"}},
		{"username with at sign", "me@home", testPassword, []string{"username"}},
		{"username with newline", "admin\n", testPassword, []string{"username"}},
		{"password 11 chars", "admin", strings.Repeat("p", 11), []string{"password"}},
		{"password 257 chars", "admin", strings.Repeat("p", 257), []string{"password"}},
		{"password empty", "admin", "", []string{"password"}},
		{"both invalid", "a", "short", []string{"username", "password"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newTestService(t)
			err := ts.Setup(tt.username, tt.password)
			if tt.wantFields == nil {
				if err != nil {
					t.Fatalf("Setup: %v", err)
				}
				return
			}
			var verr *domain.ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("Setup: err = %v, want *domain.ValidationError", err)
			}
			if len(verr.Fields) != len(tt.wantFields) {
				t.Fatalf("fields = %v, want %v", verr.Fields, tt.wantFields)
			}
			for _, field := range tt.wantFields {
				if _, ok := verr.Fields[field]; !ok {
					t.Fatalf("fields = %v, missing %q", verr.Fields, field)
				}
			}
			if tt.password != "" && strings.Contains(err.Error(), tt.password) {
				t.Fatal("error contains the password")
			}
			if !ts.SetupRequired() {
				t.Fatal("invalid setup created an account")
			}
		})
	}
}

func TestSetupOnlyOnce(t *testing.T) {
	ts := newSetUpService(t)
	calls := ts.deriver.calls.Load()
	err := ts.Setup("other", "another long password")
	if !errors.Is(err, domain.ErrSetupAlreadyDone) {
		t.Fatalf("second Setup: err = %v, want ErrSetupAlreadyDone", err)
	}
	if ts.deriver.calls.Load() != calls {
		t.Fatal("second Setup computed a hash")
	}
	account, _ := ts.store.AdminAccount()
	if account.Username != testUsername {
		t.Fatalf("account replaced by %q", account.Username)
	}
}

func TestSetupStoreErrors(t *testing.T) {
	tests := []struct {
		name      string
		createErr error
		want      error
	}{
		{"concurrent setup won", domain.ErrSetupAlreadyDone, domain.ErrSetupAlreadyDone},
		{"write failed", errStoreFailed, errStoreFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newTestService(t)
			ts.store.createErr = tt.createErr
			if err := ts.Setup(testUsername, testPassword); !errors.Is(err, tt.want) {
				t.Fatalf("Setup: err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestLogin(t *testing.T) {
	tests := []struct {
		name     string
		setUp    bool
		username string
		password string
		wantErr  error
	}{
		{"correct credentials", true, testUsername, testPassword, nil},
		{"wrong password", true, testUsername, testPassword + "!", ErrInvalidCredentials},
		{"unknown username", true, "root", testPassword, ErrInvalidCredentials},
		{"username differs in case", true, "Admin", testPassword, ErrInvalidCredentials},
		{"empty credentials", true, "", "", ErrInvalidCredentials},
		{"no account yet", false, testUsername, testPassword, ErrInvalidCredentials},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newTestService(t)
			if tt.setUp {
				if err := ts.Setup(testUsername, testPassword); err != nil {
					t.Fatalf("Setup: %v", err)
				}
			}
			calls := ts.deriver.calls.Load()
			token, err := ts.Login(tt.username, tt.password, testIP, LoginLimitStandard)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Login: err = %v, want %v", err, tt.wantErr)
			}
			if got := ts.deriver.calls.Load() - calls; got != 1 {
				t.Fatalf("Login computed %d hashes, want exactly 1", got)
			}
			if tt.wantErr != nil {
				if token != "" {
					t.Fatal("failed login returned a token")
				}
				return
			}
			if username, ok := ts.Authenticate(token); !ok || username != testUsername {
				t.Fatalf("Authenticate(new token) = %q, %v", username, ok)
			}
		})
	}
}

func TestLoginTokenIs256BitBase64URL(t *testing.T) {
	ts := newSetUpService(t)
	first := ts.mustLogin(t)
	second := ts.mustLogin(t)
	for _, token := range []string{first, second} {
		raw, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil || len(raw) != 32 {
			t.Fatalf("token %q: %d bytes, err %v", token, len(raw), err)
		}
	}
	if first == second {
		t.Fatal("two logins returned the same token")
	}
}

func TestLoginWithCorruptedHash(t *testing.T) {
	ts := newTestService(t)
	corrupted := "$argon2id$v=19$m=64,t=1,p=1$not-base64!$x"
	ts.store.account = &domain.AdminAccount{Username: testUsername, PasswordHash: corrupted}
	_, err := ts.Login(testUsername, testPassword, testIP, LoginLimitStandard)
	if err == nil || errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login: err = %v, want an internal error", err)
	}
	for _, secret := range []string{corrupted, testPassword} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error %q leaks a secret", err)
		}
	}
}

func TestLoginErrorsDoNotLeakPassword(t *testing.T) {
	ts := newSetUpService(t)
	wrong := "wrong password 1234"
	for range maxFailures + 1 {
		_, err := ts.Login(testUsername, wrong, testIP, LoginLimitStandard)
		if err == nil || strings.Contains(err.Error(), wrong) {
			t.Fatalf("Login: err = %v", err)
		}
	}
}

func TestSessionIdleTimeout(t *testing.T) {
	ts := newSetUpService(t)
	token := ts.mustLogin(t)
	for range 3 {
		ts.clock.Advance(SessionIdleTimeout - time.Minute)
		if _, ok := ts.Authenticate(token); !ok {
			t.Fatal("session expired although it was used within the idle timeout")
		}
	}
	ts.clock.Advance(SessionIdleTimeout)
	if _, ok := ts.Authenticate(token); ok {
		t.Fatal("session still valid after the idle timeout")
	}
	if n := len(ts.sessions.sessions); n != 0 {
		t.Fatalf("%d sessions kept after expiry, want 0", n)
	}
}

func TestAuthenticateRejectsUnknownTokens(t *testing.T) {
	ts := newSetUpService(t)
	token := ts.mustLogin(t)
	for _, candidate := range []string{"", "unknown", token + "x", strings.ToUpper(token)} {
		if _, ok := ts.Authenticate(candidate); ok {
			t.Fatalf("Authenticate(%q) = ok", candidate)
		}
	}
}

func TestSessionsStoreOnlyTokenHashes(t *testing.T) {
	ts := newSetUpService(t)
	token := ts.mustLogin(t)
	if _, ok := ts.sessions.sessions[hashToken(token)]; !ok {
		t.Fatal("session not keyed by the token hash")
	}
	for key, current := range ts.sessions.sessions {
		if strings.Contains(string(key[:]), token) || strings.Contains(current.username, token) {
			t.Fatal("session store holds the plain token")
		}
	}
}

func TestLogout(t *testing.T) {
	ts := newSetUpService(t)
	first := ts.mustLogin(t)
	second := ts.mustLogin(t)
	ts.Logout(first)
	ts.Logout("unknown")
	if _, ok := ts.Authenticate(first); ok {
		t.Fatal("session valid after logout")
	}
	if _, ok := ts.Authenticate(second); !ok {
		t.Fatal("logout ended another session")
	}
}

func TestSessionCapDropsOldest(t *testing.T) {
	ts := newSetUpService(t)
	tokens := make([]string, 0, MaxSessions+1)
	for range MaxSessions + 1 {
		tokens = append(tokens, ts.mustLogin(t))
		ts.clock.Advance(time.Second)
	}
	if n := len(ts.sessions.sessions); n != MaxSessions {
		t.Fatalf("%d sessions, want %d", n, MaxSessions)
	}
	if _, ok := ts.Authenticate(tokens[0]); ok {
		t.Fatal("oldest session survived the cap")
	}
	for _, token := range tokens[1:] {
		if _, ok := ts.Authenticate(token); !ok {
			t.Fatal("a newer session was dropped")
		}
	}
}

func TestLoginPurgesExpiredSessions(t *testing.T) {
	ts := newSetUpService(t)
	for range 3 {
		ts.mustLogin(t)
	}
	ts.clock.Advance(SessionIdleTimeout)
	fresh := ts.mustLogin(t)
	if n := len(ts.sessions.sessions); n != 1 {
		t.Fatalf("%d sessions after login, want 1", n)
	}
	if _, ok := ts.Authenticate(fresh); !ok {
		t.Fatal("fresh session invalid")
	}
}

func TestResetAdmin(t *testing.T) {
	ts := newSetUpService(t)
	token := ts.mustLogin(t)
	if err := ts.ResetAdmin(); err != nil {
		t.Fatalf("ResetAdmin: %v", err)
	}
	if !ts.SetupRequired() {
		t.Fatal("SetupRequired = false after reset")
	}
	if n := len(ts.sessions.sessions); n != 0 {
		t.Fatalf("%d sessions after reset, want 0", n)
	}
	if _, ok := ts.Authenticate(token); ok {
		t.Fatal("session valid after reset")
	}
	if err := ts.Setup("newadmin", "a brand new password"); err != nil {
		t.Fatalf("Setup after reset: %v", err)
	}
	if err := ts.ResetAdmin(); err != nil {
		t.Fatalf("second ResetAdmin: %v", err)
	}
}

func TestResetAdminStoreError(t *testing.T) {
	ts := newSetUpService(t)
	token := ts.mustLogin(t)
	ts.store.removeErr = errStoreFailed
	if err := ts.ResetAdmin(); !errors.Is(err, errStoreFailed) {
		t.Fatalf("ResetAdmin: err = %v, want %v", err, errStoreFailed)
	}
	if _, ok := ts.Authenticate(token); ok {
		t.Fatal("session survived a failed reset")
	}
}

func TestAuthenticateEndsSessionsOfReplacedAccount(t *testing.T) {
	ts := newSetUpService(t)
	token := ts.mustLogin(t)
	ts.store.account = &domain.AdminAccount{Username: "someone", PasswordHash: ts.store.account.PasswordHash}
	if _, ok := ts.Authenticate(token); ok {
		t.Fatal("session of a replaced account is valid")
	}
	if n := len(ts.sessions.sessions); n != 0 {
		t.Fatalf("%d sessions kept, want 0", n)
	}
}

func TestNewServiceDefaults(t *testing.T) {
	s := NewService(&fakeStore{})
	if s.hasher.params != DefaultHashParams {
		t.Fatalf("default params = %+v", s.hasher.params)
	}
	if s.now == nil {
		t.Fatal("no default clock")
	}
}
