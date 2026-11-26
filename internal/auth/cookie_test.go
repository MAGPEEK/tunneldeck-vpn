package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSetSessionCookie(t *testing.T) {
	tests := []struct {
		name     string
		secure   bool
		remember bool
	}{
		{"plain HTTP", false, false},
		{"behind HTTPS", true, false},
		{"remembered", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			SetSessionCookie(rec, "token-value", tt.secure, tt.remember)
			header := rec.Header().Get("Set-Cookie")
			for _, part := range []string{"tunneldeck_session=token-value", "Path=/", "HttpOnly", "SameSite=Strict"} {
				if !strings.Contains(header, part) {
					t.Fatalf("Set-Cookie %q lacks %q", header, part)
				}
			}
			if got := strings.Contains(header, "Secure"); got != tt.secure {
				t.Fatalf("Set-Cookie %q: Secure = %v, want %v", header, got, tt.secure)
			}
			if strings.Contains(header, "Expires") {
				t.Fatalf("Set-Cookie %q has Expires, want Max-Age only", header)
			}
			wantMaxAge := "Max-Age=7776000" // 90 days
			if got := strings.Contains(header, "Max-Age"); got != tt.remember ||
				(tt.remember && !strings.Contains(header, wantMaxAge)) {
				t.Fatalf("Set-Cookie %q: want Max-Age only when remembered (%s)", header, wantMaxAge)
			}
		})
	}
}

func TestClearSessionCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	ClearSessionCookie(rec, true)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("%d cookies, want 1", len(cookies))
	}
	c := cookies[0]
	if c.Name != SessionCookieName || c.Value != "" || c.MaxAge >= 0 || !c.HttpOnly || !c.Secure ||
		c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Fatalf("cleared cookie = %+v", c)
	}
}

func TestTokenFromRequest(t *testing.T) {
	tests := []struct {
		name   string
		cookie *http.Cookie
		want   string
	}{
		{"no cookie", nil, ""},
		{"other cookie", &http.Cookie{Name: "other", Value: "x"}, ""},
		{"session cookie", &http.Cookie{Name: SessionCookieName, Value: "abc_-123"}, "abc_-123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/session", nil)
			if tt.cookie != nil {
				req.AddCookie(tt.cookie)
			}
			if got := TokenFromRequest(req); got != tt.want {
				t.Fatalf("TokenFromRequest = %q, want %q", got, tt.want)
			}
		})
	}
}
