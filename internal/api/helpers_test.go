package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

var testNow = time.Date(2026, 11, 25, 8, 30, 0, 0, time.UTC)

type testEnv struct {
	auth          *fakeAuth
	profiles      *fakeProfiles
	connection    *fakeConnection
	firewallStore *fakeFirewallStore
	firewall      *fakeFirewall
	remote        *fakeRemoteAccess
	listener      *fakeListener
	server        *Server
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	registry := vpn.NewRegistry()
	if err := registry.Register(testProtocol, func() vpn.Driver { return fakeDriver{} }); err != nil {
		t.Fatalf("register: %v", err)
	}
	env := &testEnv{
		auth:          newFakeAuth(),
		profiles:      &fakeProfiles{},
		connection:    &fakeConnection{status: vpn.Status{State: domain.StateDisconnected}},
		firewallStore: &fakeFirewallStore{},
		firewall:      newFakeFirewall(),
		remote:        newFakeRemoteAccess(),
		listener:      &fakeListener{},
	}
	env.server = New(Deps{
		Auth:          env.auth,
		Cookies:       fakeCookies{},
		Profiles:      env.profiles,
		Drivers:       registry,
		Importer:      fakeImporter{},
		Connection:    env.connection,
		FirewallStore: env.firewallStore,
		Firewall:      env.firewall,
		System: System{
			Version: "1.2.3", ListenAddress: "192.168.1.10:8194", UIPort: testUIPort, TimeZone: "Europe/Berlin",
			Checks: func() []CheckResult { return []CheckResult{{ID: "tun-device", OK: true, Detail: "present"}} },
		},
		RemoteAccess:         env.remote,
		RemoteAccessListener: env.listener,
	}, Options{Now: func() time.Time { return testNow }, Heartbeat: 20 * time.Millisecond})
	return env
}

// storedProfile adds a valid profile whose password is testSecret.
func (e *testEnv) storedProfile(name string) domain.Profile {
	settings := domain.Settings{}
	settings.SetString("host", "vpn.example.com")
	return e.profiles.add(domain.Profile{
		Name: name, Protocol: testProtocol, Settings: settings,
		Secrets:        map[string]string{"password": testSecret},
		DailyReconnect: domain.DefaultDailyReconnect(),
	})
}

// requestOption adjusts a test request.
type requestOption func(*http.Request)

func anonymous(r *http.Request)   { r.Header.Del("Cookie") }
func withoutCSRF(r *http.Request) { r.Header.Del(CSRFHeader) }

func withHeader(name, value string) requestOption {
	return func(r *http.Request) { r.Header.Set(name, value) }
}

// do sends a request as a signed-in browser: session cookie and, for
// unsafe methods, the CSRF header.
func (e *testEnv) do(t *testing.T, method, path, body string, opts ...requestOption) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, path, reader)
	r.AddCookie(&http.Cookie{Name: testCookie, Value: testToken})
	if method != http.MethodGet {
		r.Header.Set(CSRFHeader, "1")
	}
	for _, opt := range opts {
		opt(r)
	}
	rec := httptest.NewRecorder()
	e.server.ServeHTTP(rec, r)
	assertNoSecret(t, path, rec.Body.String())
	return rec
}

func assertNoSecret(t *testing.T, path, body string) {
	t.Helper()
	if path != "/api/profiles/import" && strings.Contains(body, testSecret) {
		t.Errorf("%s: response contains the secret: %s", path, body)
	}
	if strings.Contains(body, "PRIVATE KEY") {
		t.Errorf("%s: response contains key material: %s", path, body)
	}
}

func assertStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, want, rec.Body.String())
	}
}

// assertProblem checks status, content type and the RFC 9457 members.
func assertProblem(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) problem {
	t.Helper()
	assertStatus(t, rec, status)
	if got := rec.Header().Get("Content-Type"); got != problemContentType {
		t.Errorf("content type = %q, want %q", got, problemContentType)
	}
	var p problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode problem: %v; body %s", err, rec.Body.String())
	}
	if p.Type != "about:blank" || p.Status != status || p.Code != code || p.Title != http.StatusText(status) {
		t.Errorf("problem = %+v, want status %d code %s", p, status, code)
	}
	return p
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("content type = %q, want application/json", got)
	}
	var value T
	if err := json.Unmarshal(rec.Body.Bytes(), &value); err != nil {
		t.Fatalf("decode: %v; body %s", err, rec.Body.String())
	}
	return value
}
