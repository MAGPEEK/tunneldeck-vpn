package remoteaccess

import (
	"context"
	"crypto/elliptic"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn/vpntest"
)

var errInjected = errors.New("injected failure")

// fakeKeyPairs is an in-memory certificate store.
type fakeKeyPairs struct {
	mu      sync.Mutex
	pairs   map[domain.CertificateSource]domain.KeyPair
	readErr error
	saveErr error
}

func newFakeKeyPairs() *fakeKeyPairs {
	return &fakeKeyPairs{pairs: map[domain.CertificateSource]domain.KeyPair{}}
}

func (f *fakeKeyPairs) RemoteAccessKeyPair(source domain.CertificateSource) (domain.KeyPair, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pair, ok := f.pairs[source]
	return pair, ok, f.readErr
}

func (f *fakeKeyPairs) SetRemoteAccessKeyPair(source domain.CertificateSource, pair domain.KeyPair) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.saveErr != nil {
		return f.saveErr
	}
	f.pairs[source] = pair
	return nil
}

func (f *fakeKeyPairs) get(source domain.CertificateSource) domain.KeyPair {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pairs[source]
}

// fakeFirewall records the ports it was asked to open; failPort makes one
// port fail.
type fakeFirewall struct {
	mu       sync.Mutex
	ports    []int
	failPort int
}

func (f *fakeFirewall) SetRemoteAccessPort(_ context.Context, port int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ports = append(f.ports, port)
	if f.failPort != 0 && port == f.failPort || f.failPort == -1 {
		return errInjected
	}
	return nil
}

func (f *fakeFirewall) calls() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.ports)
}

// fakeSockets listens on a free loopback port for every request and
// remembers which port was asked for.
type fakeSockets struct {
	mu        sync.Mutex
	requested []string
	bound     map[string]string // requested address → loopback address
	fail      bool
	broken    bool // Accept fails at once
}

func (f *fakeSockets) Listen(_ context.Context, network, address string) (net.Listener, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requested = append(f.requested, network+" "+address)
	if f.fail {
		return nil, errInjected
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	if f.bound == nil {
		f.bound = map[string]string{}
	}
	f.bound[address] = listener.Addr().String()
	if f.broken {
		return brokenListener{listener}, nil
	}
	return listener, nil
}

func (f *fakeSockets) address(t *testing.T, port int) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	address, ok := f.bound[fmt.Sprintf("0.0.0.0:%d", port)]
	if !ok {
		t.Fatalf("port %d was never bound", port)
	}
	return address
}

func (f *fakeSockets) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requested)
}

type brokenListener struct{ net.Listener }

func (brokenListener) Accept() (net.Conn, error) { return nil, errInjected }

type managerEnv struct {
	manager  *Manager
	pairs    *fakeKeyPairs
	firewall *fakeFirewall
	sockets  *fakeSockets
	clock    *vpntest.FakeClock
}

func newManagerEnv(t *testing.T) *managerEnv {
	t.Helper()
	env := &managerEnv{
		pairs:    newFakeKeyPairs(),
		firewall: &fakeFirewall{},
		sockets:  &fakeSockets{},
		clock:    vpntest.NewFakeClock(testNow),
	}
	env.manager = New(Config{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "served")
		}),
		KeyPairs: env.pairs,
		Firewall: env.firewall,
		Listener: env.sockets,
		Clock:    env.clock,
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := env.manager.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
	return env
}

func enabled(port int, source domain.CertificateSource) domain.RemoteAccess {
	return domain.RemoteAccess{Enabled: true, Port: port, CertificateSource: source}
}

func (e *managerEnv) apply(t *testing.T, settings domain.RemoteAccess) {
	t.Helper()
	if err := e.manager.Apply(context.Background(), settings); err != nil {
		t.Fatalf("Apply(%+v): %v", settings, err)
	}
}

// handshake connects with TLS and returns the fingerprint of the served
// certificate and the negotiated version.
func handshake(t *testing.T, address string, maxVersion uint16) (string, uint16, error) {
	t.Helper()
	conn, err := tls.Dial("tcp4", address, &tls.Config{InsecureSkipVerify: true, MaxVersion: maxVersion}) //nolint:gosec // the test checks the fingerprint itself
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = conn.Close() }()
	state := conn.ConnectionState()
	return Fingerprint(state.PeerCertificates[0].Raw), state.Version, nil
}

func fingerprintOf(t *testing.T, pair domain.KeyPair) string {
	t.Helper()
	info, err := Describe(pair.CertificatePEM)
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	return info.FingerprintSHA256
}

func assertClosed(t *testing.T, address string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", address, time.Second)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("%s still accepts connections", address)
	}
}

func get(t *testing.T, address string) string {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // self-signed test certificate
	defer client.CloseIdleConnections()
	resp, err := client.Get("https://" + address + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func TestManagerLifecycle(t *testing.T) {
	env := newManagerEnv(t)
	if env.manager.Status().Listening {
		t.Fatal("listening before Apply")
	}

	env.apply(t, enabled(8443, domain.CertificateSelfSigned))
	if status := env.manager.Status(); !status.Listening || status.LastError != "" {
		t.Fatalf("status after enable = %+v", status)
	}
	if got := env.sockets.requests(); !slices.Equal(got, []string{"tcp4 0.0.0.0:8443"}) {
		t.Fatalf("listen requests = %v", got)
	}
	first := env.sockets.address(t, 8443)
	stored := env.pairs.get(domain.CertificateSelfSigned)
	if stored.KeyPEM == "" {
		t.Fatal("no self-signed certificate stored on first enable")
	}
	fingerprint, version, err := handshake(t, first, tls.VersionTLS13)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if fingerprint != fingerprintOf(t, stored) || version != tls.VersionTLS13 {
		t.Fatalf("served %s over %x, want %s over TLS 1.3", fingerprint, version, fingerprintOf(t, stored))
	}
	if _, _, err := handshake(t, first, tls.VersionTLS11); err == nil {
		t.Fatal("TLS 1.1 handshake accepted")
	}
	if _, version, err := handshake(t, first, tls.VersionTLS12); err != nil || version != tls.VersionTLS12 {
		t.Fatalf("TLS 1.2 handshake = %x, %v", version, err)
	}
	if body := get(t, first); body != "served" {
		t.Fatalf("body = %q", body)
	}

	env.apply(t, enabled(9443, domain.CertificateSelfSigned))
	second := env.sockets.address(t, 9443)
	assertClosed(t, first)
	if body := get(t, second); body != "served" {
		t.Fatalf("body after the move = %q", body)
	}
	if env.pairs.get(domain.CertificateSelfSigned) != stored {
		t.Fatal("moving the port replaced a valid certificate")
	}

	env.apply(t, domain.RemoteAccess{Port: 9443, CertificateSource: domain.CertificateSelfSigned})
	assertClosed(t, second)
	if env.manager.Status().Listening {
		t.Fatal("listening after disable")
	}
	if got := env.firewall.calls(); !slices.Equal(got, []int{8443, 9443, 0}) {
		t.Fatalf("firewall ports = %v", got)
	}
}

func TestManagerRotatesCertificateWithoutDroppingTheListener(t *testing.T) {
	env := newManagerEnv(t)
	env.apply(t, enabled(8443, domain.CertificateSelfSigned))
	address := env.sockets.address(t, 8443)
	selfSigned := fingerprintOf(t, env.pairs.get(domain.CertificateSelfSigned))

	conn, err := tls.Dial("tcp4", address, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test certificate
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	key := newECKey(t, elliptic.P256())
	uploaded := domain.KeyPair{CertificatePEM: selfSignedPEM(t, key, testNow.Add(-time.Hour), testNow.AddDate(1, 0, 0)), KeyPEM: pkcs8PEM(t, key)}
	if err := env.pairs.SetRemoteAccessKeyPair(domain.CertificateUploaded, uploaded); err != nil {
		t.Fatal(err)
	}
	env.apply(t, enabled(8443, domain.CertificateUploaded))

	if got := env.sockets.requests(); len(got) != 1 {
		t.Fatalf("listener re-opened for a certificate change: %v", got)
	}
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatalf("existing connection dropped: %v", err)
	}
	reply := make([]byte, 12)
	if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "HTTP/1.1 200" {
		t.Fatalf("existing connection reply %q, %v", reply, err)
	}
	if fingerprint, _, err := handshake(t, address, tls.VersionTLS13); err != nil || fingerprint != fingerprintOf(t, uploaded) || fingerprint == selfSigned {
		t.Fatalf("new handshake served %s, %v; want the uploaded certificate", fingerprint, err)
	}
}

func TestManagerRenewsTheSelfSignedCertificateDaily(t *testing.T) {
	env := newManagerEnv(t)
	// Expires in 31 days: not due yet, due after one more day.
	almostDue, err := GenerateSelfSigned(testNow.AddDate(-2, 0, 31))
	if err != nil {
		t.Fatal(err)
	}
	if err := env.pairs.SetRemoteAccessKeyPair(domain.CertificateSelfSigned, almostDue); err != nil {
		t.Fatal(err)
	}
	env.apply(t, enabled(8443, domain.CertificateSelfSigned))
	address := env.sockets.address(t, 8443)
	if fingerprint, _, _ := handshake(t, address, tls.VersionTLS13); fingerprint != fingerprintOf(t, almostDue) {
		t.Fatal("a certificate that is not due was replaced")
	}
	if pending := env.clock.Pending(); !slices.Equal(pending, []time.Duration{24 * time.Hour}) {
		t.Fatalf("pending checks = %v, want one in 24h", pending)
	}

	env.clock.Advance(24 * time.Hour)
	renewed := env.pairs.get(domain.CertificateSelfSigned)
	if renewed == almostDue {
		t.Fatal("due certificate not renewed")
	}
	info, _ := Describe(renewed.CertificatePEM)
	if want := testNow.Add(24*time.Hour).AddDate(2, 0, 0); !info.NotAfter.Equal(want) {
		t.Fatalf("renewed NotAfter = %s, want %s", info.NotAfter, want)
	}
	if fingerprint, _, err := handshake(t, address, tls.VersionTLS13); err != nil || fingerprint != info.FingerprintSHA256 {
		t.Fatalf("listener serves %s, %v after renewal; want %s", fingerprint, err, info.FingerprintSHA256)
	}
	if len(env.sockets.requests()) != 1 || len(env.clock.Pending()) != 1 {
		t.Fatalf("renewal restarted the listener (%v) or lost the schedule (%v)", env.sockets.requests(), env.clock.Pending())
	}
}

func TestManagerRenewsADueCertificateOnApply(t *testing.T) {
	env := newManagerEnv(t)
	due, err := GenerateSelfSigned(testNow.AddDate(-2, 0, 10))
	if err != nil {
		t.Fatal(err)
	}
	if err := env.pairs.SetRemoteAccessKeyPair(domain.CertificateSelfSigned, due); err != nil {
		t.Fatal(err)
	}
	env.apply(t, enabled(8443, domain.CertificateSelfSigned))
	if env.pairs.get(domain.CertificateSelfSigned) == due {
		t.Fatal("due certificate kept on Apply")
	}
}

func TestManagerRenewalFailureIsReported(t *testing.T) {
	env := newManagerEnv(t)
	almostDue, err := GenerateSelfSigned(testNow.AddDate(-2, 0, 31))
	if err != nil {
		t.Fatal(err)
	}
	if err := env.pairs.SetRemoteAccessKeyPair(domain.CertificateSelfSigned, almostDue); err != nil {
		t.Fatal(err)
	}
	env.apply(t, enabled(8443, domain.CertificateSelfSigned))
	env.pairs.saveErr = errInjected
	env.clock.Advance(24 * time.Hour)
	if status := env.manager.Status(); !status.Listening || status.LastError == "" {
		t.Fatalf("status after a failed renewal = %+v", status)
	}
}

func TestManagerApplyFailures(t *testing.T) {
	tests := []struct {
		name         string
		prepare      func(*managerEnv)
		settings     domain.RemoteAccess
		wantErr      error
		wantFirewall []int
	}{
		{
			name:     "uploaded source without certificate",
			settings: enabled(8443, domain.CertificateUploaded),
			wantErr:  ErrNoCertificate,
		},
		{
			name:     "store read fails",
			prepare:  func(e *managerEnv) { e.pairs.readErr = errInjected },
			settings: enabled(8443, domain.CertificateSelfSigned),
			wantErr:  errInjected,
		},
		{
			name:     "store write fails",
			prepare:  func(e *managerEnv) { e.pairs.saveErr = errInjected },
			settings: enabled(8443, domain.CertificateSelfSigned),
			wantErr:  errInjected,
		},
		{
			name:     "port busy",
			prepare:  func(e *managerEnv) { e.sockets.fail = true },
			settings: enabled(8443, domain.CertificateSelfSigned),
			wantErr:  errInjected,
		},
		{
			name:         "firewall fails",
			prepare:      func(e *managerEnv) { e.firewall.failPort = 8443 },
			settings:     enabled(8443, domain.CertificateSelfSigned),
			wantErr:      errInjected,
			wantFirewall: []int{8443, 0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newManagerEnv(t)
			if tt.prepare != nil {
				tt.prepare(env)
			}
			err := env.manager.Apply(context.Background(), tt.settings)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Apply = %v, want %v", err, tt.wantErr)
			}
			status := env.manager.Status()
			if status.Listening || status.LastError == "" {
				t.Fatalf("status = %+v, want not listening with an error", status)
			}
			if got := env.firewall.calls(); !slices.Equal(got, tt.wantFirewall) {
				t.Fatalf("firewall ports = %v, want %v", got, tt.wantFirewall)
			}
			if len(env.clock.Pending()) != 0 {
				t.Fatal("renewal scheduled without a listener")
			}
		})
	}
}

func TestManagerFailedMoveKeepsTheOldListener(t *testing.T) {
	env := newManagerEnv(t)
	env.apply(t, enabled(8443, domain.CertificateSelfSigned))
	address := env.sockets.address(t, 8443)
	env.firewall.failPort = 9443
	if err := env.manager.Apply(context.Background(), enabled(9443, domain.CertificateSelfSigned)); !errors.Is(err, errInjected) {
		t.Fatalf("Apply = %v", err)
	}
	if body := get(t, address); body != "served" {
		t.Fatalf("old listener body = %q", body)
	}
	assertClosed(t, env.sockets.address(t, 9443))
	if got := env.firewall.calls(); !slices.Equal(got, []int{8443, 9443, 8443}) {
		t.Fatalf("firewall ports = %v, want the old port restored", got)
	}
	if status := env.manager.Status(); !status.Listening || status.LastError == "" {
		t.Fatalf("status = %+v", status)
	}

	env.firewall.failPort = 0
	env.apply(t, enabled(8443, domain.CertificateSelfSigned))
	if status := env.manager.Status(); status.LastError != "" {
		t.Fatalf("error kept after a successful apply: %+v", status)
	}
}

func TestManagerSamePortFirewallFailure(t *testing.T) {
	env := newManagerEnv(t)
	env.apply(t, enabled(8443, domain.CertificateSelfSigned))
	env.firewall.failPort = 8443
	if err := env.manager.Apply(context.Background(), enabled(8443, domain.CertificateSelfSigned)); !errors.Is(err, errInjected) {
		t.Fatalf("Apply = %v", err)
	}
	if !env.manager.Status().Listening {
		t.Fatal("listener stopped by a failed re-apply")
	}
}

func TestManagerDisableStopsTheListenerEvenWhenTheFirewallFails(t *testing.T) {
	env := newManagerEnv(t)
	env.apply(t, enabled(8443, domain.CertificateSelfSigned))
	address := env.sockets.address(t, 8443)
	env.firewall.failPort = -1
	err := env.manager.Apply(context.Background(), domain.RemoteAccess{Port: 8443, CertificateSource: domain.CertificateSelfSigned})
	if !errors.Is(err, errInjected) {
		t.Fatalf("Apply = %v", err)
	}
	assertClosed(t, address)
	if env.manager.Status().Listening {
		t.Fatal("still listening")
	}
}

func TestManagerReportsABrokenListener(t *testing.T) {
	env := newManagerEnv(t)
	env.sockets.broken = true
	env.apply(t, enabled(8443, domain.CertificateSelfSigned))
	deadline := time.Now().Add(5 * time.Second)
	for env.manager.Status().Listening {
		if time.Now().After(deadline) {
			t.Fatal("broken listener still reported as listening")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if env.manager.Status().LastError == "" {
		t.Fatal("no error for the broken listener")
	}
}

func TestManagerShutdown(t *testing.T) {
	env := newManagerEnv(t)
	env.apply(t, enabled(8443, domain.CertificateSelfSigned))
	address := env.sockets.address(t, 8443)
	if err := env.manager.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	assertClosed(t, address)
	if err := env.manager.Apply(context.Background(), enabled(8443, domain.CertificateSelfSigned)); !errors.Is(err, ErrClosed) {
		t.Fatalf("Apply after Shutdown = %v", err)
	}
	if len(env.clock.Pending()) != 0 {
		t.Fatal("renewal still scheduled after Shutdown")
	}
	env.clock.Advance(48 * time.Hour)
}

func TestNewDefaults(t *testing.T) {
	m := New(Config{})
	if _, ok := m.cfg.Listener.(*net.ListenConfig); !ok {
		t.Errorf("default listener = %T", m.cfg.Listener)
	}
	if m.cfg.Clock.Now().IsZero() || m.cfg.ReadHeaderTimeout != defaultReadHeaderTimeout || m.cfg.IdleTimeout != defaultIdleTimeout {
		t.Errorf("defaults = %+v", m.cfg)
	}
	ran := make(chan struct{})
	m.cfg.Clock.AfterFunc(time.Millisecond, func() { close(ran) })
	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("system clock never fired")
	}
}
