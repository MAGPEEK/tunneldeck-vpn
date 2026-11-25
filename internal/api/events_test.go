package api

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tunneldeck/internal/domain"
)

// sseClient reads one event stream from a test server.
type sseClient struct {
	t      *testing.T
	cancel context.CancelFunc
	body   io.ReadCloser
	lines  *bufio.Scanner
}

func openStream(t *testing.T, env *testEnv) *sseClient {
	t.Helper()
	server := httptest.NewServer(env.server)
	t.Cleanup(server.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/api/events", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: testCookie, Value: testToken})
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /api/events: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("status %d, content type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	c := &sseClient{t: t, cancel: cancel, body: resp.Body, lines: bufio.NewScanner(resp.Body)}
	if first := c.next(); first != ": connected" {
		t.Fatalf("first line = %q", first)
	}
	return c
}

func (c *sseClient) next() string {
	c.t.Helper()
	if !c.lines.Scan() {
		c.t.Fatalf("stream ended: %v", c.lines.Err())
	}
	return c.lines.Text()
}

// nextEvent skips heartbeats and blank lines and returns name and data.
func (c *sseClient) nextEvent() (string, string) {
	c.t.Helper()
	for {
		line := c.next()
		if name, ok := strings.CutPrefix(line, "event: "); ok {
			data, _ := strings.CutPrefix(c.next(), "data: ")
			return name, data
		}
	}
}

func (c *sseClient) ended() bool {
	done := make(chan bool, 1)
	go func() {
		for c.lines.Scan() {
		}
		done <- true
	}()
	select {
	case <-done:
		return true
	case <-time.After(2 * time.Second):
		return false
	}
}

func waitForSubscriber(t *testing.T, env *testEnv) chan domain.Event {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if events := env.connection.subscriber(0); events != nil {
			return events
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no subscriber")
	return nil
}

func TestEventsDeliversStateTrafficAndLog(t *testing.T) {
	env := newTestEnv(t)
	client := openStream(t, env)
	events := waitForSubscriber(t, env)

	sent := []domain.Event{
		domain.StateEvent{State: domain.StateConnected, VPNIP: "10.8.0.2", Since: testNow},
		domain.TrafficEvent{BytesIn: 100, BytesOut: 50, RateIn: 10, RateOut: 5},
		domain.LogEvent{Time: testNow, Level: domain.LogLevelInfo, Text: "hello"},
	}
	for _, e := range sent {
		events <- e
	}
	for _, want := range sent {
		name, data := client.nextEvent()
		wantData, _ := json.Marshal(want)
		if name != string(want.Kind()) || data != string(wantData) {
			t.Errorf("event %s %s, want %s %s", name, data, want.Kind(), wantData)
		}
	}
	if line := client.next(); line != "" {
		t.Errorf("event not terminated by a blank line: %q", line)
	}
	if line := client.next(); line != ": heartbeat" {
		t.Errorf("line = %q, want a heartbeat comment", line)
	}
}

func TestEventsStopOnClientDisconnect(t *testing.T) {
	env := newTestEnv(t)
	client := openStream(t, env)
	waitForSubscriber(t, env)
	client.cancel()
	deadline := time.Now().Add(2 * time.Second)
	for env.connection.cancelCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("subscription not cancelled after the client went away")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestEventsEndWhenSubscriptionCloses(t *testing.T) {
	env := newTestEnv(t)
	client := openStream(t, env)
	close(waitForSubscriber(t, env))
	if !client.ended() {
		t.Fatal("stream still open after the subscription closed")
	}
}

func TestEventsEndOnCloseStreams(t *testing.T) {
	env := newTestEnv(t)
	client := openStream(t, env)
	waitForSubscriber(t, env)
	env.server.CloseStreams()
	env.server.CloseStreams()
	if !client.ended() {
		t.Fatal("stream still open after CloseStreams")
	}
}
