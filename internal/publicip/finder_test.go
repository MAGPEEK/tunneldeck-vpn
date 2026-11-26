package publicip

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tunneldeck/internal/domain"
)

var loopback = netip.MustParseAddr("127.0.0.1")

type fixedSettings domain.PublicIPLookup

func (s fixedSettings) PublicIPLookup() domain.PublicIPLookup { return domain.PublicIPLookup(s) }

// testFinder asks url without pauses between attempts.
func testFinder(url string) *Finder {
	f := NewFinder(fixedSettings{Enabled: true, URL: url})
	f.retryDelays = []time.Duration{time.Millisecond, time.Millisecond}
	f.attemptTimeout = 200 * time.Millisecond
	return f
}

// answers serves the bodies in turn, the last one for every later request;
// a body "!<code>" answers that status instead.
func answers(t *testing.T, requests *atomic.Int32, bodies ...string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := int(requests.Add(1))
		body := bodies[min(n, len(bodies))-1]
		if code, ok := strings.CutPrefix(body, "!"); ok {
			status, _ := strconv.Atoi(code)
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

func TestLookup(t *testing.T) {
	tests := []struct {
		name         string
		bodies       []string
		want         string // "" = error
		wantRequests int32
		wantErr      string
	}{
		{name: "plain address", bodies: []string{"46.16.217.194"}, want: "46.16.217.194", wantRequests: 1},
		{name: "white space", bodies: []string{" 46.16.217.194\r\n"}, want: "46.16.217.194", wantRequests: 1},
		{name: "mapped IPv4", bodies: []string{"::ffff:46.16.217.194"}, want: "46.16.217.194", wantRequests: 1},
		{name: "third attempt works", bodies: []string{"!500", "!500", "198.51.100.7"}, want: "198.51.100.7", wantRequests: 3},
		{name: "server error", bodies: []string{"!500"}, wantRequests: 3, wantErr: "500"},
		{name: "not found", bodies: []string{"!404"}, wantRequests: 3, wantErr: "404"},
		{name: "IPv6", bodies: []string{"2001:db8::1"}, wantRequests: 3, wantErr: "not an IPv4 address"},
		{name: "html", bodies: []string{"<html>46.16.217.194</html>"}, wantRequests: 3, wantErr: "not an IPv4 address"},
		{name: "empty", bodies: []string{""}, wantRequests: 3, wantErr: "not an IPv4 address"},
		{name: "too long", bodies: []string{strings.Repeat(" ", 60) + "46.16.217.194"}, wantRequests: 3, wantErr: "longer than 64 bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int32
			server := answers(t, &requests, tt.bodies...)
			got, err := testFinder(server.URL+"/ip").Lookup(context.Background(), loopback)
			if requests.Load() != tt.wantRequests {
				t.Errorf("requests = %d, want %d", requests.Load(), tt.wantRequests)
			}
			if tt.want == "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Lookup = %v, %v; want an error mentioning %q", got, err, tt.wantErr)
				}
				return
			}
			if err != nil || got.String() != tt.want {
				t.Fatalf("Lookup = %v, %v; want %s", got, err, tt.want)
			}
		})
	}
}

func TestLookupBindsTheLocalAddress(t *testing.T) {
	var remote, agent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remote, _, _ = net.SplitHostPort(r.RemoteAddr)
		agent = r.UserAgent()
		_, _ = w.Write([]byte("203.0.113.9"))
	}))
	defer server.Close()
	if _, err := testFinder(server.URL).Lookup(context.Background(), loopback); err != nil {
		t.Fatal(err)
	}
	if remote != "127.0.0.1" || agent != "TunnelDeck-VPN" {
		t.Fatalf("request from %s with agent %q", remote, agent)
	}
	// An address the host does not have cannot be bound.
	if _, err := testFinder(server.URL).Lookup(context.Background(), netip.MustParseAddr("192.0.2.123")); err == nil {
		t.Fatal("Lookup from a foreign address succeeded")
	}
}

func TestLookupTimeout(t *testing.T) {
	release := make(chan struct{})
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
		<-release
	}))
	defer server.Close()
	defer close(release)
	f := testFinder(server.URL)
	f.attemptTimeout = 20 * time.Millisecond
	if _, err := f.Lookup(context.Background(), loopback); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Lookup = %v, want a timeout", err)
	}
	if requests.Load() != 3 {
		t.Fatalf("requests = %d, want 3", requests.Load())
	}
}

func TestLookupStopsWhenCancelled(t *testing.T) {
	var requests atomic.Int32
	server := answers(t, &requests, "!500")
	f := testFinder(server.URL)
	f.retryDelays = []time.Duration{time.Hour, time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := f.Lookup(ctx, loopback)
		done <- err
	}()
	for requests.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Lookup = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Lookup did not stop when cancelled")
	}
	if requests.Load() != 1 {
		t.Fatalf("requests = %d, want 1", requests.Load())
	}
}

func TestLookupErrorHidesTheURL(t *testing.T) {
	f := testFinder("http://127.0.0.1:1/ip?token=s3cr3t")
	_, err := f.Lookup(context.Background(), loopback)
	if err == nil || strings.Contains(err.Error(), "s3cr3t") || !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Fatalf("Lookup = %v, want an error naming the host only", err)
	}
}

func TestEnabled(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		if got := NewFinder(fixedSettings{Enabled: enabled, URL: "https://x"}).Enabled(); got != enabled {
			t.Errorf("Enabled = %v, want %v", got, enabled)
		}
	}
}

func TestLookupRefusesRedirects(t *testing.T) {
	var followed atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		followed.Add(1)
		_, _ = w.Write([]byte("203.0.113.9"))
	}))
	t.Cleanup(target.Close)
	redirect := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusFound))
	t.Cleanup(redirect.Close)

	got, err := testFinder(redirect.URL).Lookup(context.Background(), loopback)
	if err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("Lookup = %v, %v; want an error naming the redirect status", got, err)
	}
	if followed.Load() != 0 {
		t.Errorf("the redirect target was asked %d times, want 0", followed.Load())
	}
}
