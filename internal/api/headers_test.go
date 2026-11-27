package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	want := map[string]string{
		"Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
			"font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
		"X-Frame-Options":              "DENY",
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
		"Permissions-Policy":           permissionsPolicy,
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	}
	for name, value := range want {
		if got := rec.Header().Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
}

func TestAPIResponsesAreNotStored(t *testing.T) {
	tests := []struct {
		name         string
		method, path string
		opts         []requestOption
		status       int
	}{
		{name: "json", method: http.MethodGet, path: "/api/system", status: http.StatusOK},
		{name: "no content", method: http.MethodPost, path: "/api/logout", status: http.StatusNoContent},
		{name: "unauthenticated", method: http.MethodGet, path: "/api/system", opts: []requestOption{anonymous}, status: http.StatusUnauthorized},
		{name: "not found", method: http.MethodGet, path: "/api/nothing", status: http.StatusNotFound},
		{name: "csrf", method: http.MethodPut, path: "/api/firewall", opts: []requestOption{withoutCSRF}, status: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			rec := env.do(t, tt.method, tt.path, "", tt.opts...)
			assertStatus(t, rec, tt.status)
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
		})
	}
}
