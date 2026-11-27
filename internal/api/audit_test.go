package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"tunneldeck/internal/domain"
)

// auditSummary renders recorded events for comparison.
func auditSummary(events []domain.AuditEvent) string {
	lines := []string{}
	for _, e := range events {
		lines = append(lines, fmt.Sprintf("%s %s %s user=%q x%d", e.Type, e.ClientIP, e.Access, e.Username, e.Count))
	}
	return strings.Join(lines, "; ")
}

func TestLoginIsAudited(t *testing.T) {
	const correct = `{"username":"admin","password":"correct-password"}`
	const wrong = `{"username":"guessed-user","password":"guessed-password"}`
	tests := []struct {
		name       string
		body       string
		retryAfter time.Duration
		remoteLock bool
		loginErr   error
		opts       []requestOption
		want       string
	}{
		{name: "success", body: correct, want: `signedIn 192.0.2.1 lan user="admin" x1`},
		{name: "success remote", body: correct, opts: []requestOption{viaHTTPS}, want: `signedIn 192.0.2.1 remote user="admin" x1`},
		{name: "wrong credentials keep no username", body: wrong, want: `wrongCredentials 192.0.2.1 lan user="" x1`},
		{name: "cooldown", body: correct, retryAfter: time.Second, want: `rateLimited 192.0.2.1 lan user="" x1`},
		{
			name: "remote lock", body: correct, retryAfter: time.Minute, remoteLock: true, opts: []requestOption{viaHTTPS},
			want: `remoteLocked 192.0.2.1 remote user="" x1`,
		},
		{name: "internal error is not audited", body: correct, loginErr: errors.New("disk full"), want: ""},
		{name: "invalid body", body: `{"username":"admin","password":"x","stay":true}`, want: `invalidBody 192.0.2.1 lan user="" x1`},
		{name: "peer address only", body: wrong, opts: []requestOption{withHeader("X-Forwarded-For", "203.0.113.9"), withRemoteAddr("198.51.100.7:4711")},
			want: `wrongCredentials 198.51.100.7 lan user="" x1`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			env.auth.retryAfter = tt.retryAfter
			env.auth.remoteLock = tt.remoteLock
			env.auth.loginErr = tt.loginErr
			env.do(t, http.MethodPost, "/api/login", tt.body, append([]requestOption{anonymous}, tt.opts...)...)
			events := env.audit.recorded()
			if got := auditSummary(events); got != tt.want {
				t.Fatalf("audited %s, want %s", got, tt.want)
			}
			for _, e := range events {
				if !e.Time.Equal(testNow) || e.Time.Location() != time.UTC {
					t.Errorf("time = %s, want %s UTC", e.Time, testNow)
				}
				if strings.Contains(fmt.Sprint(e), "guessed") || strings.Contains(fmt.Sprint(e), "password") {
					t.Errorf("event holds attempted credentials: %+v", e)
				}
			}
		})
	}
}

func TestLogoutIsAudited(t *testing.T) {
	tests := []struct {
		method, path string
		want         string
	}{
		{http.MethodPost, "/api/logout", `signedOut 192.0.2.1 lan user="admin" x1`},
		{http.MethodDelete, "/api/sessions", `signedOutEverywhere 192.0.2.1 lan user="admin" x1`},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			env := newTestEnv(t)
			assertStatus(t, env.do(t, tt.method, tt.path, ""), http.StatusNoContent)
			if got := auditSummary(env.audit.recorded()); got != tt.want {
				t.Fatalf("audited %s, want %s", got, tt.want)
			}
		})
	}
}

func TestCSRFRejectionsAreAudited(t *testing.T) {
	tests := []struct {
		name string
		opts []requestOption
		want string
	}{
		{name: "missing header", opts: []requestOption{withoutCSRF}, want: `csrfRejected 192.0.2.1 lan user="" x1`},
		{name: "wrong header", opts: []requestOption{withHeader(CSRFHeader, "yes")}, want: `csrfRejected 192.0.2.1 lan user="" x1`},
		{name: "foreign origin", opts: []requestOption{withHeader("Origin", "https://evil.example")}, want: `csrfRejected 192.0.2.1 lan user="" x1`},
		{name: "foreign origin remote", opts: []requestOption{viaHTTPS, withHeader("Origin", "https://evil.example")},
			want: `csrfRejected 192.0.2.1 remote user="" x1`},
		{name: "accepted", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			env.do(t, http.MethodPut, "/api/public-ip-lookup", `{"enabled":true,"url":"https://api.ipify.org"}`, tt.opts...)
			if got := auditSummary(env.audit.recorded()); got != tt.want {
				t.Fatalf("audited %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRefusedBodiesAreAudited(t *testing.T) {
	huge := `{"name":"` + strings.Repeat("a", maxBodyBytes) + `"}`
	tests := []struct {
		name, method, path, body string
		opts                     []requestOption
		want                     string
	}{
		{name: "login too large", method: http.MethodPost, path: "/api/login", body: huge, opts: []requestOption{anonymous},
			want: `bodyTooLarge 192.0.2.1 lan user="" x1`},
		{name: "profile too large", method: http.MethodPost, path: "/api/profiles", body: huge, want: `bodyTooLarge 192.0.2.1 lan user="" x1`},
		{name: "import not JSON", method: http.MethodPost, path: "/api/profiles/import", body: "client\nremote x", want: `invalidBody 192.0.2.1 lan user="" x1`},
		{name: "trailing data", method: http.MethodPost, path: "/api/login", body: `{} {}`, opts: []requestOption{anonymous},
			want: `invalidBody 192.0.2.1 lan user="" x1`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			assertProblem(t, env.do(t, tt.method, tt.path, tt.body, tt.opts...), http.StatusBadRequest, CodeBadRequest)
			if got := auditSummary(env.audit.recorded()); got != tt.want {
				t.Fatalf("audited %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRepeatedNotFoundIsAuditedAsScan(t *testing.T) {
	env := newTestEnv(t)
	scanner := withRemoteAddr("198.51.100.7:4711")
	for i := range scanThreshold - 1 {
		env.do(t, http.MethodGet, fmt.Sprintf("/api/wp-admin/%d", i), "", anonymous, scanner)
	}
	env.do(t, http.MethodGet, "/api/profiles/missing", "")     // a known route answering 404
	env.do(t, http.MethodGet, "/api/.env", "", anonymous)      // another client
	env.do(t, http.MethodPost, "/api/system", "{}", anonymous) // 405, not 404
	if events := env.audit.recorded(); len(events) != 0 {
		t.Fatalf("audited before the threshold: %s", auditSummary(events))
	}
	env.do(t, http.MethodGet, "/api/.git/config", "", anonymous, scanner)
	env.do(t, http.MethodGet, "/api/admin", "", anonymous, scanner)
	want := `possibleScan 198.51.100.7 lan user="" x10; possibleScan 198.51.100.7 lan user="" x1`
	if got := auditSummary(env.audit.recorded()); got != want {
		t.Fatalf("audited %s, want %s", got, want)
	}
}

func TestScanDetectorWindow(t *testing.T) {
	d := newScanDetector()
	start := testNow
	for i := range scanThreshold - 1 {
		if n := d.notFound("10.0.0.1", start.Add(time.Duration(i)*time.Second)); n != 0 {
			t.Fatalf("request %d reported %d", i+1, n)
		}
	}
	if n := d.notFound("10.0.0.1", start.Add(scanWindow)); n != 0 {
		t.Fatalf("a request after the window counted towards the old one: %d", n)
	}
	for range scanThreshold - 2 {
		d.notFound("10.0.0.1", start.Add(scanWindow))
	}
	if n := d.notFound("10.0.0.1", start.Add(scanWindow)); n != scanThreshold {
		t.Fatalf("threshold reported %d, want %d", n, scanThreshold)
	}
}

func TestScanDetectorBoundsClients(t *testing.T) {
	d := newScanDetector()
	for i := range scanMaxClients + 5 {
		d.notFound(fmt.Sprintf("client-%d", i), testNow)
	}
	if len(d.clients) > scanMaxClients {
		t.Fatalf("tracks %d clients, limit %d", len(d.clients), scanMaxClients)
	}
}

func TestGetAudit(t *testing.T) {
	env := newTestEnv(t)
	first := testNow.Add(-time.Hour)
	env.audit.page = domain.AuditPage{
		Events: []domain.AuditEvent{
			{ID: 9, Time: testNow, FirstTime: first, Type: domain.AuditCSRFRejected, ClientIP: "10.8.0.9", Access: domain.LoginAccessRemote, Count: 4},
			{ID: 8, Time: first, Type: domain.AuditSignedIn, ClientIP: "10.8.0.6", Access: domain.LoginAccessRemote, Username: "admin", Count: 1},
		},
		HasMore:         true,
		RecentWarnings:  4,
		NewRemoteSignIn: &domain.AuditEvent{ID: 8, Time: first, Type: domain.AuditSignedIn, ClientIP: "10.8.0.6", Access: domain.LoginAccessRemote, Username: "admin", Count: 1},
	}
	rec := env.do(t, http.MethodGet, "/api/audit?limit=2&before=10&filter=security", "")
	assertStatus(t, rec, http.StatusOK)
	want := `{"entries":[` +
		`{"id":9,"time":"2026-11-25T08:30:00Z","firstTime":"2026-11-25T07:30:00Z","type":"csrfRejected","severity":"warning","clientIp":"10.8.0.9","access":"remote","count":4},` +
		`{"id":8,"time":"2026-11-25T07:30:00Z","type":"signedIn","severity":"info","clientIp":"10.8.0.6","access":"remote","username":"admin","count":1}],` +
		`"hasMore":true,"recentWarnings":4,` +
		`"newRemoteSignIn":{"id":8,"time":"2026-11-25T07:30:00Z","type":"signedIn","severity":"info","clientIp":"10.8.0.6","access":"remote","username":"admin","count":1}}`
	if got := strings.TrimSpace(rec.Body.String()); got != want {
		t.Fatalf("body =\n%s\nwant\n%s", got, want)
	}
	wantQuery := domain.AuditQuery{Limit: 2, Before: 10, Filter: domain.AuditFilterSecurity, WarningsSince: testNow.Add(-24 * time.Hour)}
	if env.audit.query != wantQuery {
		t.Fatalf("query = %+v, want %+v", env.audit.query, wantQuery)
	}
}

func TestGetAuditQuery(t *testing.T) {
	tests := []struct {
		query string
		want  domain.AuditQuery // ignored when bad
		bad   bool
	}{
		{query: "", want: domain.AuditQuery{Limit: 50}},
		{query: "?limit=500&filter=failures", want: domain.AuditQuery{Limit: 500, Filter: domain.AuditFilterFailures}},
		{query: "?before=1", want: domain.AuditQuery{Limit: 50, Before: 1}},
		{query: "?limit=0", bad: true},
		{query: "?limit=501", bad: true},
		{query: "?limit=x", bad: true},
		{query: "?before=0", bad: true},
		{query: "?before=-3", bad: true},
		{query: "?filter=all", bad: true},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			env := newTestEnv(t)
			rec := env.do(t, http.MethodGet, "/api/audit"+tt.query, "")
			if tt.bad {
				assertProblem(t, rec, http.StatusBadRequest, CodeBadRequest)
				return
			}
			assertStatus(t, rec, http.StatusOK)
			if body := strings.TrimSpace(rec.Body.String()); body != `{"entries":[],"hasMore":false,"recentWarnings":0}` {
				t.Errorf("body = %s", body)
			}
			tt.want.WarningsSince = testNow.Add(-24 * time.Hour)
			if env.audit.query != tt.want {
				t.Errorf("query = %+v, want %+v", env.audit.query, tt.want)
			}
		})
	}
}
