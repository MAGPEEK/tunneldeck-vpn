package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/store"
)

type recordingAudit struct{ events []domain.AuditEvent }

func (r *recordingAudit) Record(event domain.AuditEvent) { r.events = append(r.events, event) }

func TestAuditLockEvents(t *testing.T) {
	log := &recordingAudit{}
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.FixedZone("CET", 3600))
	events := auditLockEvents{log: log, now: func() time.Time { return now }}
	events.RemoteLockStarted("10.8.0.9")
	events.RemoteLockEnded()
	want := []domain.AuditEvent{
		{Time: now.UTC(), Type: domain.AuditRemoteLockStarted, ClientIP: "10.8.0.9", Access: domain.LoginAccessRemote},
		{Time: now.UTC(), Type: domain.AuditRemoteLockEnded, Access: domain.LoginAccessRemote},
	}
	if fmt.Sprint(log.events) != fmt.Sprint(want) {
		t.Fatalf("events = %+v, want %+v", log.events, want)
	}
}

// TestServeAuditsLoginsAndCSRF runs the server and checks that a failed
// login and a CSRF rejection end up in audit-log.json once it stops.
func TestServeAuditsLoginsAndCSRF(t *testing.T) {
	cfg := testConfig(t)
	a, err := startApp(context.Background(), cfg, host{runner: failingRunner{}, network: fakeNetwork{}, controlPath: shortSocketPath(t)})
	if err != nil {
		t.Fatalf("startApp: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.run(ctx) }()

	post := func(path string, csrf bool) *http.Response {
		req, err := http.NewRequest(http.MethodPost, "http://"+cfg.Listen+path, strings.NewReader(`{"username":"guess","password":"guessed-password"}`))
		if err != nil {
			t.Fatal(err)
		}
		if csrf {
			req.Header.Set("X-TunnelDeck-Request", "1")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		_ = resp.Body.Close()
		return resp
	}
	if resp := post("/api/login", true); resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Errorf("login: status %d, X-Frame-Options %q", resp.StatusCode, resp.Header.Get("X-Frame-Options"))
	}
	if resp := post("/api/login", false); resp.StatusCode != http.StatusForbidden {
		t.Errorf("login without CSRF header: status %d", resp.StatusCode)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(cfg.DataDir, store.AuditLogFileName))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if strings.Contains(string(data), "guess") {
		t.Fatalf("audit log holds the attempted credentials: %s", data)
	}
	var doc struct{ Events []domain.AuditEvent }
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var got []string
	for _, e := range doc.Events {
		got = append(got, fmt.Sprintf("%s %s %s", e.Type, e.ClientIP, e.Access))
	}
	if want := "[wrongCredentials 127.0.0.1 lan csrfRejected 127.0.0.1 lan]"; fmt.Sprint(got) != want {
		t.Fatalf("audit log = %v, want %s", got, want)
	}
}
