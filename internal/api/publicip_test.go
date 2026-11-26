package api

import (
	"net/http"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
)

func TestGetPublicIPLookup(t *testing.T) {
	env := newTestEnv(t)
	rec := env.do(t, http.MethodGet, "/api/public-ip-lookup", "")
	assertStatus(t, rec, http.StatusOK)
	if body := strings.TrimSpace(rec.Body.String()); body != `{"enabled":true,"url":"https://api.ipify.org"}` {
		t.Fatalf("body = %s", body)
	}
}

func TestPublicIPLookupRequiresSessionAndCSRF(t *testing.T) {
	env := newTestEnv(t)
	body := `{"enabled":false,"url":"https://api.ipify.org"}`
	assertProblem(t, env.do(t, http.MethodGet, "/api/public-ip-lookup", "", anonymous), http.StatusUnauthorized, CodeUnauthenticated)
	assertProblem(t, env.do(t, http.MethodPut, "/api/public-ip-lookup", body, anonymous), http.StatusUnauthorized, CodeUnauthenticated)
	assertProblem(t, env.do(t, http.MethodPut, "/api/public-ip-lookup", body, withoutCSRF), http.StatusForbidden, CodeCSRF)
	if env.publicIP.PublicIPLookup() != domain.DefaultPublicIPLookup() || env.connection.lookupChanges != 0 {
		t.Fatal("a refused request changed the setting")
	}
}

func TestPutPublicIPLookup(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		want     domain.PublicIPLookup // zero = refused
		status   int
		code     string
		wantCode string // field code of "url"
	}{
		{name: "switch off", body: `{"enabled":false,"url":"https://api.ipify.org"}`, status: http.StatusOK,
			want: domain.PublicIPLookup{URL: "https://api.ipify.org"}},
		{name: "other service, trimmed", body: `{"enabled":true,"url":"  http://ifconfig.me/ip "}`, status: http.StatusOK,
			want: domain.PublicIPLookup{Enabled: true, URL: "http://ifconfig.me/ip"}},
		{name: "empty url", body: `{"enabled":true,"url":""}`, status: http.StatusUnprocessableEntity,
			code: CodeValidationFailed, wantCode: "required"},
		{name: "not http", body: `{"enabled":true,"url":"ftp://example.com"}`, status: http.StatusUnprocessableEntity,
			code: CodeValidationFailed, wantCode: "public_ip_url_invalid"},
		{name: "credentials", body: `{"enabled":true,"url":"https://u:s3cr3t@example.com"}`, status: http.StatusUnprocessableEntity,
			code: CodeValidationFailed, wantCode: "url_credentials_not_allowed"},
		{name: "unknown field", body: `{"enabled":true,"url":"https://api.ipify.org","x":1}`, status: http.StatusBadRequest, code: CodeBadRequest},
		{name: "wrong type", body: `{"enabled":"yes","url":"https://api.ipify.org"}`, status: http.StatusBadRequest, code: CodeBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			rec := env.do(t, http.MethodPut, "/api/public-ip-lookup", tt.body)
			if tt.code != "" {
				p := assertProblem(t, rec, tt.status, tt.code)
				if tt.wantCode != "" && p.FieldCodes["url"].Code != tt.wantCode {
					t.Errorf("field codes = %v, want url %s", p.FieldCodes, tt.wantCode)
				}
				if strings.Contains(rec.Body.String(), "s3cr3t") {
					t.Errorf("problem echoes the URL: %s", rec.Body.String())
				}
				if env.publicIP.PublicIPLookup() != domain.DefaultPublicIPLookup() || env.connection.lookupChanges != 0 {
					t.Error("an invalid request was stored or applied")
				}
				return
			}
			assertStatus(t, rec, tt.status)
			if got := decode[publicIPLookupBody](t, rec); domain.PublicIPLookup(got) != tt.want {
				t.Fatalf("response = %+v, want %+v", got, tt.want)
			}
			if env.publicIP.PublicIPLookup() != tt.want || env.connection.lookupChanges != 1 {
				t.Fatalf("stored %+v, applied %d times", env.publicIP.PublicIPLookup(), env.connection.lookupChanges)
			}
		})
	}
}
