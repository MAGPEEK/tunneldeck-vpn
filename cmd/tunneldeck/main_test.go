package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"tunneldeck/internal/api"
	"tunneldeck/internal/auth"
	"tunneldeck/internal/config"
	"tunneldeck/internal/control"
	"tunneldeck/internal/domain"
	"tunneldeck/internal/netguard"
)

func TestRouter(t *testing.T) {
	handler := func(body string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) })
	}
	router := newRouter(handler("api"), handler("spa"))
	tests := []struct{ path, want string }{
		{"/api/system", "api"},
		{"/api/unknown", "api"},
		{"/", "spa"},
		{"/profiles", "spa"},
	}
	for _, tt := range tests {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))
		if rec.Body.String() != tt.want {
			t.Errorf("%s served by %q, want %q", tt.path, rec.Body.String(), tt.want)
		}
	}
}

type fakeNetwork struct {
	defaultIP netip.Addr
	routeErr  error
	tunnel    []netip.Addr
	tunnelErr error
}

func (n fakeNetwork) DefaultRouteIPv4() (netip.Addr, error)       { return n.defaultIP, n.routeErr }
func (n fakeNetwork) InterfaceIPv4s(string) ([]netip.Addr, error) { return n.tunnel, n.tunnelErr }
func addr(s string) netip.Addr                                    { return netip.MustParseAddr(s) }
func addrs(s ...string) (list []netip.Addr) {
	for _, a := range s {
		list = append(list, addr(a))
	}
	return
}

func TestResolveListenAddress(t *testing.T) {
	lan := fakeNetwork{defaultIP: addr("192.168.1.10"), tunnel: addrs("10.8.0.2")}
	tests := []struct {
		name       string
		configured string
		goos       string
		network    fakeNetwork
		want       string
		wantErr    bool
	}{
		{name: "default route interface", goos: "linux", network: lan, want: "192.168.1.10:8194"},
		{name: "configured", configured: "0.0.0.0:9000", goos: "linux", network: lan, want: "0.0.0.0:9000"},
		{name: "configured all interfaces", configured: ":9000", goos: "linux", network: lan, want: ":9000"},
		{name: "configured tunnel address", configured: "10.8.0.2:8194", goos: "linux", network: lan, wantErr: true},
		{name: "default route through the tunnel", goos: "linux", network: fakeNetwork{defaultIP: addr("10.8.0.2"), tunnel: addrs("10.8.0.2")}, wantErr: true},
		{name: "no default route", goos: "linux", network: fakeNetwork{routeErr: errors.New("unreachable")}, wantErr: true},
		{name: "tunnel lookup fails", goos: "linux", network: fakeNetwork{defaultIP: addr("192.168.1.10"), tunnelErr: errors.New("x")}, wantErr: true},
		{name: "windows fallback", goos: "windows", network: lan, want: fallbackListenAddress},
		{name: "windows configured", configured: "127.0.0.1:18194", goos: "windows", want: "127.0.0.1:18194"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveListenAddress(tt.configured, tt.goos, tt.network)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveListenAddress = %q, want an error", got)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("resolveListenAddress = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestSystemNetwork(t *testing.T) {
	ips, err := systemNetwork{}.InterfaceIPv4s("no-such-interface0")
	if err != nil || len(ips) != 0 {
		t.Errorf("InterfaceIPv4s of a missing interface = %v, %v", ips, err)
	}
	if ip, err := (systemNetwork{}).DefaultRouteIPv4(); err == nil && !ip.Is4() {
		t.Errorf("DefaultRouteIPv4 = %v", ip)
	}
}

type fakeAccounts struct{ account *domain.AdminAccount }

func (f *fakeAccounts) AdminAccount() (domain.AdminAccount, bool) {
	if f.account == nil {
		return domain.AdminAccount{}, false
	}
	return *f.account, true
}
func (f *fakeAccounts) CreateAdminAccount(a domain.AdminAccount) error { f.account = &a; return nil }
func (f *fakeAccounts) RemoveAdminAccount() error                      { f.account = nil; return nil }
func (f *fakeAccounts) RememberedSessions() []domain.RememberedSession { return nil }
func (f *fakeAccounts) SetRememberedSessions([]domain.RememberedSession) error {
	return nil
}

func newAdapterService(t *testing.T) authAdapter {
	t.Helper()
	service := auth.NewService(&fakeAccounts{}, auth.WithHashParams(auth.HashParams{MemoryKiB: 64, Iterations: 1, Parallelism: 1, KeyLength: 32, SaltLength: 16}))
	if err := service.Setup("admin", "correct horse battery"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	return authAdapter{service}
}

func TestAuthAdapterMapsErrors(t *testing.T) {
	adapter := newAdapterService(t)
	if _, err := adapter.Login("admin", "correct horse battery", api.LoginClient{IP: "192.0.2.1"}, false); err != nil {
		t.Fatalf("Login: %v", err)
	}
	client := api.LoginClient{IP: "192.0.2.2"}
	_, err := adapter.Login("admin", "wrong password!", client, false)
	var credentials *api.InvalidCredentialsError
	if !errors.As(err, &credentials) || !errors.Is(err, api.ErrInvalidCredentials) || credentials.RetryAfter != 10*time.Second {
		t.Errorf("wrong password = %v, want *api.InvalidCredentialsError with a 10s cooldown", err)
	}
	_, err = adapter.Login("admin", "correct horse battery", client, false)
	var rateLimit *api.RateLimitError
	if !errors.As(err, &rateLimit) || rateLimit.RetryAfter <= 0 || rateLimit.Remote {
		t.Errorf("attempt during the cooldown = %v, want *api.RateLimitError of the client", err)
	}
}

func TestAuthAdapterAppliesTheRemoteLimitOnTheRemoteListener(t *testing.T) {
	tests := []struct {
		name       string
		remote     bool
		wantLocked bool
	}{
		{name: "remote listener", remote: true, wantLocked: true},
		{name: "LAN listener", remote: false, wantLocked: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := newAdapterService(t)
			for i := range 10 {
				client := api.LoginClient{IP: fmt.Sprintf("203.0.113.%d", i), Remote: tt.remote}
				if _, err := adapter.Login("admin", "wrong password!", client, false); !errors.Is(err, api.ErrInvalidCredentials) {
					t.Fatalf("failure %d = %v, want api.ErrInvalidCredentials", i+1, err)
				}
			}
			_, err := adapter.Login("admin", "correct horse battery", api.LoginClient{IP: "203.0.113.99", Remote: tt.remote}, false)
			var rateLimit *api.RateLimitError
			if locked := errors.As(err, &rateLimit) && rateLimit.Remote; locked != tt.wantLocked {
				t.Errorf("login from a new client = %v, want remote lock %v", err, tt.wantLocked)
			}
		})
	}
}

func TestSessionCookies(t *testing.T) {
	rec := httptest.NewRecorder()
	sessionCookies{}.Set(rec, "tok", false, false)
	cookie := rec.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, auth.SessionCookieName+"=tok") || strings.Contains(cookie, "Secure") || !strings.Contains(cookie, "HttpOnly") ||
		strings.Contains(cookie, "Max-Age") {
		t.Errorf("Set-Cookie = %q", cookie)
	}
	rec = httptest.NewRecorder()
	sessionCookies{}.Set(rec, "tok", false, true)
	if cookie := rec.Header().Get("Set-Cookie"); !strings.Contains(cookie, "Max-Age=7776000") {
		t.Errorf("remembered Set-Cookie = %q, want a 90-day Max-Age", cookie)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: "tok"})
	if got := (sessionCookies{}).Token(r); got != "tok" {
		t.Errorf("Token = %q", got)
	}
	rec = httptest.NewRecorder()
	sessionCookies{}.Clear(rec, true)
	if cookie := rec.Header().Get("Set-Cookie"); !strings.Contains(cookie, "Max-Age=0") || !strings.Contains(cookie, "Secure") {
		t.Errorf("clear Set-Cookie = %q", cookie)
	}
}

func TestProfileImporter(t *testing.T) {
	draft, err := profileImporter{}.Import(domain.ProtocolOpenVPN, "client\nremote vpn.example.com 1194\nup /bin/sh\nca ca.crt\n")
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if host, _ := draft.Settings.String("remoteHost"); host != "vpn.example.com" || len(draft.Warnings) == 0 ||
		!slices.ContainsFunc(draft.Warnings, func(w api.ImportWarning) bool { return w.File == "ca.crt" }) ||
		!slices.Contains(draft.Missing, "caCert") {
		t.Errorf("draft = %+v", draft)
	}
	if _, err := (profileImporter{}).Import("ipsec", ""); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("unknown protocol = %v", err)
	}
	var v *domain.ValidationError
	if _, err := (profileImporter{}).Import(domain.ProtocolOpenVPN, "<ca>\n"); !errors.As(err, &v) {
		t.Errorf("unclosed block = %v", err)
	}
}

func TestProfileImporterWireGuard(t *testing.T) {
	conf := "[Interface]\nPrivateKey = cGxhY2Vob2xkZXItcHJpdmF0ZS1rZXktMzItYnl0ZXM=\nAddress = 10.66.0.2/32\nDNS = 10.66.0.1\n" +
		"[Peer]\nPublicKey = cGxhY2Vob2xkZXItcHVibGljLWtleS0zMi1ieXRlcyE=\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"
	draft, err := profileImporter{}.Import(domain.ProtocolWireGuard, conf)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if endpoint, _ := draft.Settings.String("endpoint"); endpoint != "vpn.example.com:51820" || draft.Secrets["privateKey"] == "" ||
		!slices.ContainsFunc(draft.Warnings, func(w api.ImportWarning) bool { return w.Code == "dns_ignored" && w.Line == 4 }) {
		t.Errorf("draft = %+v", draft)
	}
	var v *domain.ValidationError
	if _, err := (profileImporter{}).Import(domain.ProtocolWireGuard, "client\n"); !errors.As(err, &v) {
		t.Errorf("not a config = %v", err)
	}
}

func TestDriversServeOpenVPNWireGuardAndIPsec(t *testing.T) {
	a := &app{host: host{runner: failingRunner{}}, guard: netguard.New(failingRunner{})}
	registry, err := a.drivers()
	if err != nil {
		t.Fatal(err)
	}
	want := []domain.Protocol{domain.ProtocolIPsec, domain.ProtocolOpenVPN, domain.ProtocolWireGuard}
	if got := registry.Protocols(); !slices.Equal(got, want) {
		t.Fatalf("protocols = %v, want %v", got, want)
	}
	for _, protocol := range want {
		factory, err := registry.Lookup(protocol)
		if err != nil {
			t.Fatal(err)
		}
		if d := factory(); d.Protocol() != protocol || len(d.Describe().Sections) == 0 {
			t.Errorf("driver of %s = %T", protocol, d)
		}
	}
}

func TestToCheckResults(t *testing.T) {
	got := toCheckResults([]netguard.CheckResult{
		{ID: "ip", OK: false, DetailCode: "ipToolFailed", Params: map[string]string{"error": "missing"}, Detail: "missing", Hint: "install"},
		{ID: "rule-counters", OK: false, Warning: true, DetailCode: "countersOff", Detail: "off", Hint: "load"},
	})
	want := []api.CheckResult{
		{ID: "ip", OK: false, DetailCode: "ipToolFailed", Params: map[string]string{"error": "missing"}, Detail: "missing", Hint: "install"},
		{ID: "rule-counters", OK: false, Warning: true, DetailCode: "countersOff", Detail: "off", Hint: "load"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("checks = %+v, want %+v", got, want)
	}
}

func TestRunRejectsBadInvocations(t *testing.T) {
	env := func(string) string { return "" }
	if err := run(context.Background(), []string{"explode"}, env); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("unknown command = %v", err)
	}
	if err := run(context.Background(), []string{"reset-admin", "extra"}, env); err == nil {
		t.Error("extra argument accepted")
	}
	badLevel := func(key string) string {
		if key == config.EnvLogLevel {
			return "loud"
		}
		return ""
	}
	if err := run(context.Background(), nil, badLevel); err == nil {
		t.Error("invalid config accepted")
	}
}

// failingRunner behaves like a machine without iptables and ip.
type failingRunner struct{}

func (failingRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	return "", &netguard.CommandError{Name: name, Args: args, ExitCode: -1, Err: errors.New("not installed")}
}

func freeAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	address := l.Addr().String()
	_ = l.Close()
	return address
}

func testConfig(t *testing.T) config.Config {
	t.Helper()
	cfg, err := config.Load(func(key string) string {
		switch key {
		case config.EnvDataDir:
			return t.TempDir()
		case config.EnvListen:
			return freeAddress(t)
		}
		return ""
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "tdmain")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, control.SocketName)
}

func TestServeAndResetAdminOverTheControlSocket(t *testing.T) {
	cfg := testConfig(t)
	socket := shortSocketPath(t)
	a, err := startApp(context.Background(), cfg, host{runner: failingRunner{}, network: fakeNetwork{}, controlPath: socket})
	if err != nil {
		t.Fatalf("startApp: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.run(ctx) }()
	base := "http://" + cfg.Listen

	if session := getSession(t, base); !session.SetupRequired {
		t.Fatalf("session = %+v, want setup required", session)
	}
	if err := a.auth.Setup("admin", "correct horse battery"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	system := getJSON[map[string]any](t, base+"/api/system", http.StatusUnauthorized)
	if system["code"] != api.CodeUnauthenticated {
		t.Errorf("system without session = %v", system)
	}
	if a.control != nil {
		if err := resetAdminCommand(context.Background(), cfg, socket); err != nil {
			t.Fatalf("reset-admin over the socket: %v", err)
		}
		if session := getSession(t, base); !session.SetupRequired {
			t.Errorf("setup not required after reset-admin")
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("server did not shut down")
	}
	if _, err := os.Stat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("control socket left behind: %v", err)
	}
}

func TestStartAppFailsOnBusyPort(t *testing.T) {
	cfg := testConfig(t)
	busy, err := net.Listen("tcp4", cfg.Listen)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = busy.Close() }()
	if _, err := startApp(context.Background(), cfg, host{runner: failingRunner{}, network: fakeNetwork{}, controlPath: shortSocketPath(t)}); err == nil {
		t.Fatal("startApp succeeded on a busy port")
	}
}

func TestResetAdminFromEnvironment(t *testing.T) {
	cfg := testConfig(t)
	st, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	if err := st.CreateAdminAccount(domain.AdminAccount{Username: "admin", PasswordHash: "x"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	cfg.ResetAdmin = true
	a, err := startApp(context.Background(), cfg, host{runner: failingRunner{}, network: fakeNetwork{}, controlPath: shortSocketPath(t)})
	if err != nil {
		t.Fatalf("startApp: %v", err)
	}
	defer func() { _ = a.shutdown() }()
	if !a.auth.SetupRequired() {
		t.Error("admin still present with TUNNELDECK_RESET_ADMIN=1")
	}
}

func TestResetAdminWithoutServerEditsTheStore(t *testing.T) {
	cfg := testConfig(t)
	st, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	if err := st.CreateAdminAccount(domain.AdminAccount{Username: "admin", PasswordHash: "x"}); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := resetAdminCommand(context.Background(), cfg, shortSocketPath(t)); err != nil {
		t.Fatalf("resetAdminCommand: %v", err)
	}
	reopened, err := openStore(cfg)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, exists := reopened.AdminAccount(); exists {
		t.Error("admin account still stored")
	}
}

type sessionJSON struct {
	SetupRequired bool `json:"setupRequired"`
}

func getSession(t *testing.T, base string) sessionJSON {
	t.Helper()
	return getJSON[sessionJSON](t, base+"/api/session", http.StatusOK)
}

func getJSON[T any](t *testing.T, url string, wantStatus int) T {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != wantStatus {
		t.Fatalf("GET %s = %d, want %d", url, resp.StatusCode, wantStatus)
	}
	var value T
	if err := json.NewDecoder(resp.Body).Decode(&value); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return value
}
