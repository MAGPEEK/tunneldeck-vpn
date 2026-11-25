package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"tunneldeck/internal/domain"
)

// loopbackSockets binds every requested listener to a free loopback port.
type loopbackSockets struct {
	mu        sync.Mutex
	requested []string
	address   string
}

func (s *loopbackSockets) Listen(_ context.Context, network, address string) (net.Listener, error) {
	listener, err := net.Listen(network, "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requested = append(s.requested, network+" "+address)
	s.address = listener.Addr().String()
	return listener, nil
}

func (s *loopbackSockets) bound() (string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.address, append([]string(nil), s.requested...)
}

func TestStartAppServesStoredRemoteAccessOverHTTPS(t *testing.T) {
	cfg := testConfig(t)
	st, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	if err := st.SetRemoteAccess(domain.RemoteAccess{Enabled: true, Port: 18443, CertificateSource: domain.CertificateSelfSigned}); err != nil {
		t.Fatalf("SetRemoteAccess: %v", err)
	}
	sockets := &loopbackSockets{}
	a, err := startApp(context.Background(), cfg, host{runner: failingRunner{}, network: fakeNetwork{}, controlPath: shortSocketPath(t), sockets: sockets})
	if err != nil {
		t.Fatalf("startApp: %v", err)
	}
	address, requested := sockets.bound()
	if len(requested) != 1 || requested[0] != "tcp4 0.0.0.0:18443" {
		t.Fatalf("listen requests = %v", requested)
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // self-signed certificate under test
	defer client.CloseIdleConnections()
	resp, err := client.Get("https://" + address + "/api/session")
	if err != nil {
		t.Fatalf("GET over HTTPS: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Strict-Transport-Security") != "max-age=31536000" {
		t.Fatalf("status %d, HSTS %q", resp.StatusCode, resp.Header.Get("Strict-Transport-Security"))
	}
	if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Fatalf("TLS state = %+v", resp.TLS)
	}

	if err := a.shutdown(); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if conn, err := net.DialTimeout("tcp4", address, time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("HTTPS listener still open after shutdown")
	}
}

func TestPlainListenerSendsNoHSTS(t *testing.T) {
	cfg := testConfig(t)
	a, err := startApp(context.Background(), cfg, host{runner: failingRunner{}, network: fakeNetwork{}, controlPath: shortSocketPath(t)})
	if err != nil {
		t.Fatalf("startApp: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("run: %v", err)
		}
	}()
	resp, err := http.Get("http://" + cfg.Listen + "/api/session")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.Header.Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS sent over plain HTTP")
	}
	if a.remote.Status().Listening {
		t.Fatal("remote access listening although it is off")
	}
}
