package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/remoteaccess"
)

// viaHTTPS marks a test request as arriving on the HTTPS listener.
func viaHTTPS(r *http.Request) {
	*r = *r.WithContext(context.WithValue(r.Context(), secureListenerKey{}, true))
}

func withRemoteAddr(address string) requestOption {
	return func(r *http.Request) { r.RemoteAddr = address }
}

func newKeyPair(t *testing.T) domain.KeyPair {
	t.Helper()
	pair, err := remoteaccess.GenerateSelfSigned(testNow)
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	return pair
}

// assertNoKey fails when the response holds any base64 line of the keys.
func assertNoKey(t *testing.T, rec *httptest.ResponseRecorder, pairs ...domain.KeyPair) {
	t.Helper()
	body := rec.Body.String()
	for _, pair := range pairs {
		lines := strings.Split(strings.TrimSpace(pair.KeyPEM), "\n")
		for _, line := range lines[1 : len(lines)-1] {
			if strings.Contains(body, line) {
				t.Fatalf("response contains key material: %s", body)
			}
		}
	}
}

func TestGetRemoteAccess(t *testing.T) {
	env := newTestEnv(t)
	rec := env.do(t, http.MethodGet, "/api/remote-access", "")
	assertStatus(t, rec, http.StatusOK)
	want := `{"enabled":false,"port":8443,"certificateSource":"selfSigned","certificate":null,"listening":false}`
	if body := strings.TrimSpace(rec.Body.String()); body != want {
		t.Fatalf("body = %s, want %s", body, want)
	}

	pair := newKeyPair(t)
	env.remote.pairs[domain.CertificateSelfSigned] = pair
	env.remote.settings.Enabled = true
	env.listener.status = remoteaccess.Status{Listening: true, LastError: "renew failed"}
	rec = env.do(t, http.MethodGet, "/api/remote-access", "")
	assertNoKey(t, rec, pair)
	got := decode[remoteAccessResponse](t, rec)
	info, _ := remoteaccess.Describe(pair.CertificatePEM)
	if got.Certificate == nil || got.Certificate.FingerprintSHA256 != info.FingerprintSHA256 || !got.Certificate.SelfSigned ||
		got.Certificate.Subject != "CN=tunneldeck" || !got.Certificate.NotAfter.Equal(info.NotAfter) {
		t.Fatalf("certificate = %+v, want %+v", got.Certificate, info)
	}
	if !got.Listening || got.LastError != "renew failed" || !got.Enabled {
		t.Fatalf("state = %+v", got)
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if notAfter, _ := raw["certificate"].(map[string]any)["notAfter"].(string); !strings.HasSuffix(notAfter, "Z") {
		t.Errorf("notAfter %q is not RFC 3339 UTC", notAfter)
	}
}

func TestRemoteAccessRequiresSessionAndCSRF(t *testing.T) {
	env := newTestEnv(t)
	assertProblem(t, env.do(t, http.MethodGet, "/api/remote-access", "", anonymous), http.StatusUnauthorized, CodeUnauthenticated)
	body := `{"enabled":true,"port":8443,"certificateSource":"selfSigned"}`
	assertProblem(t, env.do(t, http.MethodPut, "/api/remote-access", body, anonymous), http.StatusUnauthorized, CodeUnauthenticated)
	assertProblem(t, env.do(t, http.MethodPut, "/api/remote-access", body, withoutCSRF), http.StatusForbidden, CodeCSRF)
	assertProblem(t, env.do(t, http.MethodPost, "/api/remote-access/certificate", `{}`, withoutCSRF), http.StatusForbidden, CodeCSRF)
	assertProblem(t, env.do(t, http.MethodPut, "/api/remote-access", body, withHeader("Origin", "https://evil.example")), http.StatusForbidden, CodeCSRF)
	if len(env.listener.calls()) != 0 {
		t.Fatal("listener applied for a refused request")
	}
}

func TestPutRemoteAccess(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		prepare   func(*testEnv)
		status    int
		code      string
		wantField string
	}{
		{name: "enable", body: `{"enabled":true,"port":8443,"certificateSource":"selfSigned"}`, status: http.StatusOK},
		{name: "disable", body: `{"enabled":false,"port":8443,"certificateSource":"selfSigned"}`, status: http.StatusOK},
		{
			name: "uploaded with a certificate", body: `{"enabled":true,"port":9443,"certificateSource":"uploaded"}`, status: http.StatusOK,
			prepare: func(e *testEnv) { e.remote.pairs[domain.CertificateUploaded] = newKeyPair(t) },
		},
		{name: "uploaded without a certificate", body: `{"enabled":true,"port":8443,"certificateSource":"uploaded"}`, status: http.StatusUnprocessableEntity, code: CodeValidationFailed, wantField: "certificateSource"},
		{name: "unknown source", body: `{"enabled":true,"port":8443,"certificateSource":"acme"}`, status: http.StatusUnprocessableEntity, code: CodeValidationFailed, wantField: "certificateSource"},
		{name: "port out of range", body: `{"enabled":true,"port":0,"certificateSource":"selfSigned"}`, status: http.StatusUnprocessableEntity, code: CodeValidationFailed, wantField: "port"},
		{name: "UI port", body: `{"enabled":true,"port":8194,"certificateSource":"selfSigned"}`, status: http.StatusUnprocessableEntity, code: CodeValidationFailed, wantField: "port"},
		{name: "UI port while disabled", body: `{"enabled":false,"port":8194,"certificateSource":"selfSigned"}`, status: http.StatusUnprocessableEntity, code: CodeValidationFailed, wantField: "port"},
		{
			name: "enabled TCP firewall port", body: `{"enabled":true,"port":8443,"certificateSource":"selfSigned"}`,
			status: http.StatusUnprocessableEntity, code: CodeValidationFailed, wantField: "port",
			prepare: func(e *testEnv) {
				e.firewallStore.setRules(hostPortRule("r", domain.ProtocolTCP, 8443))
			},
		},
		{
			name: "disabled or UDP firewall port", body: `{"enabled":true,"port":8443,"certificateSource":"selfSigned"}`, status: http.StatusOK,
			prepare: func(e *testEnv) {
				disabled := hostPortRule("a", domain.ProtocolTCP, 8443)
				disabled.Enabled = false
				e.firewallStore.setRules(disabled, hostPortRule("b", domain.ProtocolUDP, 8443))
			},
		},
		{
			name: "firewall port while disabled", body: `{"enabled":false,"port":8443,"certificateSource":"selfSigned"}`, status: http.StatusOK,
			prepare: func(e *testEnv) {
				e.firewallStore.setRules(hostPortRule("r", domain.ProtocolTCP, 8443))
			},
		},
		{name: "unknown field", body: `{"enabled":true,"port":8443,"certificateSource":"selfSigned","x":1}`, status: http.StatusBadRequest, code: CodeBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			if tt.prepare != nil {
				tt.prepare(env)
			}
			rec := env.do(t, http.MethodPut, "/api/remote-access", tt.body)
			if tt.code != "" {
				p := assertProblem(t, rec, tt.status, tt.code)
				if tt.wantField != "" && p.Fields[tt.wantField] == "" {
					t.Errorf("fields = %v, want %s", p.Fields, tt.wantField)
				}
				assertEveryFieldCoded(t, p)
				if len(env.listener.calls()) != 0 || env.remote.RemoteAccess() != domain.DefaultRemoteAccess() {
					t.Error("an invalid request was stored or applied")
				}
				return
			}
			assertStatus(t, rec, tt.status)
			var want remoteAccessRequest
			if err := json.Unmarshal([]byte(tt.body), &want); err != nil {
				t.Fatal(err)
			}
			got := decode[remoteAccessResponse](t, rec)
			if got.Enabled != want.Enabled || got.Port != want.Port || got.CertificateSource != want.CertificateSource || got.Listening != want.Enabled {
				t.Fatalf("response = %+v, want %+v", got, want)
			}
			if calls := env.listener.calls(); !slices.Equal(calls, []domain.RemoteAccess{domain.RemoteAccess(want)}) {
				t.Fatalf("applied %v", calls)
			}
			if env.remote.RemoteAccess() != domain.RemoteAccess(want) {
				t.Fatalf("stored %+v", env.remote.RemoteAccess())
			}
		})
	}
}

func TestPutRemoteAccessRollsBackWhenApplyFails(t *testing.T) {
	env := newTestEnv(t)
	env.listener.failOnce = errBoom
	rec := env.do(t, http.MethodPut, "/api/remote-access", `{"enabled":true,"port":9443,"certificateSource":"selfSigned"}`)
	p := assertProblem(t, rec, http.StatusInternalServerError, CodeRemoteAccessFailed)
	if strings.Contains(p.Detail, "boom") {
		t.Errorf("detail leaks the error: %q", p.Detail)
	}
	if got := env.remote.RemoteAccess(); got != domain.DefaultRemoteAccess() {
		t.Fatalf("stored after rollback = %+v, want the previous setting", got)
	}
	calls := env.listener.calls()
	if len(calls) != 2 || calls[1] != domain.DefaultRemoteAccess() {
		t.Fatalf("applied %v, want the new and then the previous setting", calls)
	}
}

func TestPutRemoteAccessStoreFailure(t *testing.T) {
	env := newTestEnv(t)
	env.remote.failSet = errBoom
	assertProblem(t, env.do(t, http.MethodPut, "/api/remote-access", `{"enabled":true,"port":8443,"certificateSource":"selfSigned"}`),
		http.StatusInternalServerError, CodeInternal)
	if len(env.listener.calls()) != 0 {
		t.Error("applied after the store failed")
	}
}

func uploadBody(t *testing.T, pair domain.KeyPair) string {
	t.Helper()
	body, err := json.Marshal(certificateUpload{CertificatePEM: pair.CertificatePEM, KeyPEM: pair.KeyPEM})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestUploadCertificate(t *testing.T) {
	env := newTestEnv(t)
	pair := newKeyPair(t)
	rec := env.do(t, http.MethodPost, "/api/remote-access/certificate", uploadBody(t, pair))
	assertStatus(t, rec, http.StatusOK)
	assertNoKey(t, rec, pair)
	stored, ok := env.remote.pair(domain.CertificateUploaded)
	if !ok || stored.KeyPEM == "" {
		t.Fatal("certificate not stored")
	}
	if env.remote.RemoteAccess() != domain.DefaultRemoteAccess() || len(env.listener.calls()) != 0 {
		t.Fatal("upload changed or applied the setting")
	}
	if got := decode[remoteAccessResponse](t, rec); got.CertificateSource != domain.CertificateSelfSigned || got.Certificate != nil {
		t.Fatalf("response = %+v, want the unchanged self-signed state", got)
	}

	rec = env.do(t, http.MethodPut, "/api/remote-access", `{"enabled":true,"port":8443,"certificateSource":"uploaded"}`)
	assertStatus(t, rec, http.StatusOK)
	if got := decode[remoteAccessResponse](t, rec); got.Certificate == nil || got.Certificate.Subject != "CN=tunneldeck" {
		t.Fatalf("certificate after switching = %+v", got.Certificate)
	}

	replacement := newKeyPair(t)
	rec = env.do(t, http.MethodPost, "/api/remote-access/certificate", uploadBody(t, replacement))
	assertStatus(t, rec, http.StatusOK)
	assertNoKey(t, rec, pair, replacement)
	if calls := env.listener.calls(); len(calls) != 2 {
		t.Fatalf("applied %v, want the uploaded certificate served at once", calls)
	}
}

func TestUploadCertificateRejects(t *testing.T) {
	pair := newKeyPair(t)
	other := newKeyPair(t)
	tests := []struct {
		name      string
		body      string
		status    int
		code      string
		wantField string
	}{
		{name: "mismatched key", body: uploadBody(t, domain.KeyPair{CertificatePEM: pair.CertificatePEM, KeyPEM: other.KeyPEM}), status: http.StatusUnprocessableEntity, code: CodeValidationFailed, wantField: "keyPem"},
		{name: "garbage", body: `{"certificatePem":"x","keyPem":"y"}`, status: http.StatusUnprocessableEntity, code: CodeValidationFailed, wantField: "certificatePem"},
		{name: "unknown field", body: `{"certificatePem":"x","keyPem":"y","password":"z"}`, status: http.StatusBadRequest, code: CodeBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			rec := env.do(t, http.MethodPost, "/api/remote-access/certificate", tt.body)
			p := assertProblem(t, rec, tt.status, tt.code)
			if tt.wantField != "" && p.Fields[tt.wantField] == "" {
				t.Errorf("fields = %v, want %s", p.Fields, tt.wantField)
			}
			assertEveryFieldCoded(t, p)
			assertNoKey(t, rec, pair, other)
			if _, ok := env.remote.pair(domain.CertificateUploaded); ok {
				t.Error("rejected certificate stored")
			}
		})
	}
}

func TestUploadCertificateFailures(t *testing.T) {
	pair := newKeyPair(t)

	env := newTestEnv(t)
	env.remote.failSet = errBoom
	assertProblem(t, env.do(t, http.MethodPost, "/api/remote-access/certificate", uploadBody(t, pair)), http.StatusInternalServerError, CodeInternal)

	env = newTestEnv(t)
	env.remote.pairs[domain.CertificateUploaded] = pair
	env.remote.settings = domain.RemoteAccess{Enabled: true, Port: 8443, CertificateSource: domain.CertificateUploaded}
	env.listener.failOnce = errBoom
	rec := env.do(t, http.MethodPost, "/api/remote-access/certificate", uploadBody(t, newKeyPair(t)))
	assertProblem(t, rec, http.StatusInternalServerError, CodeRemoteAccessFailed)
	assertNoKey(t, rec, pair)
}

func TestFirewallRejectsTheRemoteAccessPort(t *testing.T) {
	const rule = `{"name":"r","direction":"inbound","protocol":"%s","destination":{"kind":"host"},"destinationPort":{"from":8443},"enabled":%t}`
	tests := []struct {
		name     string
		enabled  bool
		protocol string
		ruleOn   bool
		wantErr  bool
	}{
		{name: "enabled TCP rule", enabled: true, protocol: "tcp", ruleOn: true, wantErr: true},
		{name: "enabled tcp+udp rule", enabled: true, protocol: "tcp+udp", ruleOn: true, wantErr: true},
		{name: "disabled rule", enabled: true, protocol: "tcp"},
		{name: "UDP rule", enabled: true, protocol: "udp", ruleOn: true},
		{name: "remote access off", enabled: false, protocol: "tcp", ruleOn: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			env.remote.settings.Enabled = tt.enabled
			rec := env.do(t, http.MethodPut, "/api/firewall", firewallBody(fmt.Sprintf(rule, tt.protocol, tt.ruleOn)))
			if !tt.wantErr {
				assertStatus(t, rec, http.StatusOK)
				return
			}
			p := assertProblem(t, rec, http.StatusUnprocessableEntity, CodeValidationFailed)
			if p.Fields["rules[0].destinationPort"] == "" {
				t.Errorf("fields = %v", p.Fields)
			}
			if len(env.firewall.applied) != 0 {
				t.Error("firewall applied")
			}
		})
	}
}

func TestSecureListener(t *testing.T) {
	var secure bool
	handler := SecureListener(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { secure = isSecureListener(r) }))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rec.Header().Get("Strict-Transport-Security"); got != "max-age=31536000" || !secure {
		t.Fatalf("HSTS = %q, secure = %v", got, secure)
	}
	if isSecureListener(httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Fatal("plain request marked secure")
	}
}

func TestSessionCookieIsSecureOnTheHTTPSListener(t *testing.T) {
	env := newTestEnv(t)
	rec := env.do(t, http.MethodPost, "/api/login", `{"username":"admin","password":"correct-password"}`, anonymous, viaHTTPS)
	assertStatus(t, rec, http.StatusNoContent)
	if cookie := rec.Header().Get("Set-Cookie"); !strings.Contains(cookie, "Secure") || !strings.Contains(cookie, "HttpOnly") {
		t.Fatalf("Set-Cookie = %q, want Secure", cookie)
	}
	rec = env.do(t, http.MethodPost, "/api/logout", "", viaHTTPS)
	if cookie := rec.Header().Get("Set-Cookie"); !strings.Contains(cookie, "Secure") || !strings.Contains(cookie, "Max-Age=0") {
		t.Fatalf("logout Set-Cookie = %q, want a Secure deletion", cookie)
	}
}

func TestLoginLimitSelection(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		https      bool
		want       LoginClient
	}{
		{name: "LAN over HTTP", remoteAddr: "192.168.1.20:5000", want: LoginClient{IP: "192.168.1.20"}},
		{name: "public over HTTP", remoteAddr: "203.0.113.9:5000", want: LoginClient{IP: "203.0.113.9"}},
		{name: "public over HTTPS", remoteAddr: "203.0.113.9:5000", https: true, want: LoginClient{IP: "203.0.113.9", Remote: true}},
		{name: "CGNAT over HTTPS", remoteAddr: "100.64.0.5:5000", https: true, want: LoginClient{IP: "100.64.0.5", Remote: true}},
		{name: "10/8 over HTTPS", remoteAddr: "10.8.0.6:5000", https: true, want: LoginClient{IP: "10.8.0.6"}},
		{name: "172.16/12 over HTTPS", remoteAddr: "172.20.1.1:5000", https: true, want: LoginClient{IP: "172.20.1.1"}},
		{name: "192.168/16 over HTTPS", remoteAddr: "192.168.1.20:5000", https: true, want: LoginClient{IP: "192.168.1.20"}},
		{name: "loopback over HTTPS", remoteAddr: "127.0.0.1:5000", https: true, want: LoginClient{IP: "127.0.0.1"}},
		{name: "link-local over HTTPS", remoteAddr: "169.254.10.1:5000", https: true, want: LoginClient{IP: "169.254.10.1"}},
		{name: "mapped private over HTTPS", remoteAddr: "[::ffff:192.168.1.20]:5000", https: true, want: LoginClient{IP: "::ffff:192.168.1.20"}},
		{name: "unparseable over HTTPS", remoteAddr: "garbage", https: true, want: LoginClient{IP: "garbage", Remote: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			opts := []requestOption{anonymous, withRemoteAddr(tt.remoteAddr)}
			if tt.https {
				opts = append(opts, viaHTTPS)
			}
			env.do(t, http.MethodPost, "/api/login", `{"username":"admin","password":"x"}`, opts...)
			if env.auth.loginClient != tt.want {
				t.Fatalf("client = %+v, want %+v", env.auth.loginClient, tt.want)
			}
		})
	}
}
