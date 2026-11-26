package api

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestGetSession(t *testing.T) {
	tests := []struct {
		name      string
		setupDone bool
		opts      []requestOption
		want      sessionResponse
	}{
		{name: "signed in", setupDone: true, want: sessionResponse{Authenticated: true, Username: testUser, RememberAvailable: true}},
		{name: "signed out", setupDone: true, opts: []requestOption{anonymous}, want: sessionResponse{RememberAvailable: true}},
		{name: "setup required", opts: []requestOption{anonymous}, want: sessionResponse{SetupRequired: true, RememberAvailable: true}},
		{name: "HTTPS listener", setupDone: true, opts: []requestOption{anonymous, viaHTTPS}, want: sessionResponse{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			env.auth.setupDone = tt.setupDone
			rec := env.do(t, http.MethodGet, "/api/session", "", tt.opts...)
			assertStatus(t, rec, http.StatusOK)
			if got := decode[sessionResponse](t, rec); got != tt.want {
				t.Errorf("session = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSetup(t *testing.T) {
	tests := []struct {
		name      string
		setupDone bool
		body      string
		status    int
		code      string
	}{
		{name: "creates the admin", body: `{"username":"admin","password":"long-enough-pw"}`, status: http.StatusNoContent},
		{name: "short password", body: `{"username":"admin","password":"short"}`, status: http.StatusUnprocessableEntity, code: CodeValidationFailed},
		{name: "already done", setupDone: true, body: `{"username":"admin","password":"long-enough-pw"}`, status: http.StatusConflict, code: CodeSetupDone},
		{name: "bad json", body: `{"username":`, status: http.StatusBadRequest, code: CodeBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			env.auth.setupDone = tt.setupDone
			rec := env.do(t, http.MethodPost, "/api/setup", tt.body, anonymous)
			if tt.code == "" {
				assertStatus(t, rec, tt.status)
				return
			}
			p := assertProblem(t, rec, tt.status, tt.code)
			if tt.code == CodeValidationFailed && p.Fields["password"] == "" {
				t.Errorf("fields = %v, want password", p.Fields)
			}
		})
	}
}

func TestLogin(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		retryAfter time.Duration
		status     int
		code       string
		wantRetry  string
	}{
		{name: "sets the cookie", body: `{"username":"admin","password":"correct-password"}`, status: http.StatusNoContent},
		{name: "wrong password", body: `{"username":"admin","password":"wrong-password"}`, status: http.StatusUnauthorized, code: CodeInvalidCredentials},
		{
			name: "rate limited rounds up", body: `{"username":"admin","password":"correct-password"}`,
			retryAfter: 1500 * time.Millisecond, status: http.StatusTooManyRequests, code: CodeRateLimited, wantRetry: "2",
		},
		{
			name: "rate limited below a second", body: `{"username":"admin","password":"correct-password"}`,
			retryAfter: 10 * time.Millisecond, status: http.StatusTooManyRequests, code: CodeRateLimited, wantRetry: "1",
		},
		{name: "unknown field", body: `{"username":"admin","password":"x","stay":true}`, status: http.StatusBadRequest, code: CodeBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			env.auth.retryAfter = tt.retryAfter
			rec := env.do(t, http.MethodPost, "/api/login", tt.body, anonymous)
			if tt.code != "" {
				assertProblem(t, rec, tt.status, tt.code)
				if got := rec.Header().Get("Retry-After"); got != tt.wantRetry {
					t.Errorf("Retry-After = %q, want %q", got, tt.wantRetry)
				}
				return
			}
			assertStatus(t, rec, tt.status)
			cookie := rec.Header().Get("Set-Cookie")
			if !strings.Contains(cookie, testCookie+"=new-token") || strings.Contains(cookie, "Secure") {
				t.Errorf("Set-Cookie = %q", cookie)
			}
			if env.auth.loginClient != (LoginClient{IP: "192.0.2.1"}) {
				t.Errorf("client = %+v, want the RemoteAddr host 192.0.2.1 with the standard limit", env.auth.loginClient)
			}
		})
	}
}

func TestLoginRemember(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		opts         []requestOption
		wantRemember bool
	}{
		{name: "LAN with remember", body: `{"username":"admin","password":"correct-password","remember":true}`, wantRemember: true},
		{name: "LAN without remember", body: `{"username":"admin","password":"correct-password","remember":false}`},
		{name: "LAN without the field", body: `{"username":"admin","password":"correct-password"}`},
		{
			name: "HTTPS listener ignores remember", body: `{"username":"admin","password":"correct-password","remember":true}`,
			opts: []requestOption{viaHTTPS},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			rec := env.do(t, http.MethodPost, "/api/login", tt.body, append([]requestOption{anonymous}, tt.opts...)...)
			assertStatus(t, rec, http.StatusNoContent)
			if env.auth.remembered != tt.wantRemember {
				t.Errorf("remember passed to Login = %v, want %v", env.auth.remembered, tt.wantRemember)
			}
			cookie := rec.Header().Get("Set-Cookie")
			if got := strings.Contains(cookie, "Max-Age="); got != tt.wantRemember {
				t.Errorf("Set-Cookie = %q, want Max-Age only with remember", cookie)
			}
		})
	}
}

func TestLoginIgnoresForwardedFor(t *testing.T) {
	env := newTestEnv(t)
	env.do(t, http.MethodPost, "/api/login", `{"username":"admin","password":"x"}`, anonymous,
		withHeader("X-Forwarded-For", "203.0.113.9"))
	if env.auth.loginClient.IP != "192.0.2.1" {
		t.Errorf("client = %+v, want IP 192.0.2.1", env.auth.loginClient)
	}
}

func TestLogout(t *testing.T) {
	env := newTestEnv(t)
	rec := env.do(t, http.MethodPost, "/api/logout", "")
	assertStatus(t, rec, http.StatusNoContent)
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Errorf("Set-Cookie = %q, want a deletion", rec.Header().Get("Set-Cookie"))
	}
	if _, ok := env.auth.Authenticate(testToken); ok {
		t.Error("session still valid after logout")
	}
	assertProblem(t, env.do(t, http.MethodPost, "/api/logout", ""), http.StatusUnauthorized, CodeUnauthenticated)
}

func TestLogoutStoreErrorStillClearsCookie(t *testing.T) {
	env := newTestEnv(t)
	env.auth.logoutErr = errors.New("disk full")
	rec := env.do(t, http.MethodPost, "/api/logout", "")
	assertProblem(t, rec, http.StatusInternalServerError, CodeInternal)
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Errorf("Set-Cookie = %q, want a deletion", rec.Header().Get("Set-Cookie"))
	}
}

func TestLogoutEverywhere(t *testing.T) {
	env := newTestEnv(t)
	env.auth.tokens["other-token"] = testUser
	rec := env.do(t, http.MethodDelete, "/api/sessions", "")
	assertStatus(t, rec, http.StatusNoContent)
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Errorf("Set-Cookie = %q, want a deletion", rec.Header().Get("Set-Cookie"))
	}
	for _, token := range []string{testToken, "other-token"} {
		if _, ok := env.auth.Authenticate(token); ok {
			t.Errorf("session %s still valid", token)
		}
	}
	assertProblem(t, env.do(t, http.MethodDelete, "/api/sessions", ""), http.StatusUnauthorized, CodeUnauthenticated)
	assertProblem(t, env.do(t, http.MethodDelete, "/api/sessions", "", withoutCSRF), http.StatusForbidden, CodeCSRF)
}

func TestLogoutEverywhereStoreError(t *testing.T) {
	env := newTestEnv(t)
	env.auth.logoutErr = errors.New("disk full")
	assertProblem(t, env.do(t, http.MethodDelete, "/api/sessions", ""), http.StatusInternalServerError, CodeInternal)
}
