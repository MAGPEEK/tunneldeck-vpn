package api

import (
	"net/http"
	"strings"
	"testing"
)

var privateEndpoints = []struct{ method, path string }{
	{http.MethodPost, "/api/logout"},
	{http.MethodGet, "/api/drivers"},
	{http.MethodGet, "/api/profiles"},
	{http.MethodPost, "/api/profiles"},
	{http.MethodPost, "/api/profiles/import"},
	{http.MethodGet, "/api/profiles/p1"},
	{http.MethodPut, "/api/profiles/p1"},
	{http.MethodDelete, "/api/profiles/p1"},
	{http.MethodGet, "/api/connection"},
	{http.MethodPost, "/api/connection/connect"},
	{http.MethodPost, "/api/connection/disconnect"},
	{http.MethodPost, "/api/connection/reconnect"},
	{http.MethodGet, "/api/logs"},
	{http.MethodGet, "/api/events"},
	{http.MethodGet, "/api/host-access"},
	{http.MethodPut, "/api/host-access"},
	{http.MethodGet, "/api/system"},
}

func TestPrivateEndpointsRequireASession(t *testing.T) {
	for _, e := range privateEndpoints {
		t.Run(e.method+" "+e.path, func(t *testing.T) {
			env := newTestEnv(t)
			assertProblem(t, env.do(t, e.method, e.path, "{}", anonymous), http.StatusUnauthorized, CodeUnauthenticated)
			bogus := withHeader("Cookie", testCookie+"=forged")
			assertProblem(t, env.do(t, e.method, e.path, "{}", anonymous, bogus), http.StatusUnauthorized, CodeUnauthenticated)
		})
	}
}

func TestCSRF(t *testing.T) {
	unsafe := []struct{ method, path string }{
		{http.MethodPost, "/api/setup"},
		{http.MethodPost, "/api/login"},
		{http.MethodPost, "/api/logout"},
		{http.MethodPost, "/api/profiles"},
		{http.MethodPut, "/api/profiles/p1"},
		{http.MethodDelete, "/api/profiles/p1"},
		{http.MethodPost, "/api/connection/disconnect"},
		{http.MethodPut, "/api/host-access"},
	}
	tests := []struct {
		name string
		opts []requestOption
	}{
		{name: "missing header", opts: []requestOption{withoutCSRF}},
		{name: "wrong header value", opts: []requestOption{withHeader(CSRFHeader, "yes")}},
		{name: "foreign origin", opts: []requestOption{withHeader("Origin", "http://evil.example")}},
		{name: "null origin", opts: []requestOption{withHeader("Origin", "null")}},
		{name: "same host other port", opts: []requestOption{withHeader("Origin", "http://example.com:8080")}},
	}
	for _, e := range unsafe {
		for _, tt := range tests {
			t.Run(e.method+" "+e.path+" "+tt.name, func(t *testing.T) {
				env := newTestEnv(t)
				assertProblem(t, env.do(t, e.method, e.path, "{}", tt.opts...), http.StatusForbidden, CodeCSRF)
			})
		}
	}
}

func TestCSRFAcceptsMatchingOrigin(t *testing.T) {
	env := newTestEnv(t)
	rec := env.do(t, http.MethodPost, "/api/connection/disconnect", "", withHeader("Origin", "http://EXAMPLE.com"))
	assertStatus(t, rec, http.StatusAccepted)
}

func TestUnmatchedRoutes(t *testing.T) {
	env := newTestEnv(t)
	assertProblem(t, env.do(t, http.MethodGet, "/api/unknown", ""), http.StatusNotFound, CodeNotFound)
	rec := env.do(t, http.MethodPatch, "/api/profiles", "{}")
	assertProblem(t, rec, http.StatusMethodNotAllowed, CodeMethodNotAllowed)
	if got := rec.Header().Values("Allow"); strings.Join(got, ",") != "GET,POST" {
		t.Errorf("Allow = %v, want GET, POST", got)
	}
}

func TestRequestBodyLimits(t *testing.T) {
	big := `{"name":"` + strings.Repeat("a", maxBodyBytes) + `"}`
	tests := []struct {
		name, body, want string
	}{
		{name: "too large", body: big, want: "at most"},
		{name: "empty", body: "", want: "empty"},
		{name: "trailing data", body: `{"profileId":"p1"} {}`, want: "single JSON value"},
		{name: "wrong type", body: `{"profileId":5}`, want: "wrong type"},
		{name: "unknown field", body: `{"profile":"p1"}`, want: "not known"},
		{name: "not json", body: `<xml/>`, want: "not valid JSON"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			p := assertProblem(t, env.do(t, http.MethodPost, "/api/connection/connect", tt.body), http.StatusBadRequest, CodeBadRequest)
			if !strings.Contains(p.Detail, tt.want) {
				t.Errorf("detail = %q, want it to mention %q", p.Detail, tt.want)
			}
		})
	}
}

func TestClientIPWithoutPort(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "unix"
	if got := clientIP(r); got != "unix" {
		t.Errorf("clientIP = %q", got)
	}
}
