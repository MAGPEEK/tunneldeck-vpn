package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tunneldeck/internal/config"
)

func TestHealthURL(t *testing.T) {
	tests := []struct {
		listen, want string
		wantErr      bool
	}{
		{listen: "192.168.1.10:8194", want: "http://192.168.1.10:8194/api/session"},
		{listen: "0.0.0.0:8194", want: "http://127.0.0.1:8194/api/session"},
		{listen: ":9000", want: "http://127.0.0.1:9000/api/session"},
		{listen: "127.0.0.1:18194", want: "http://127.0.0.1:18194/api/session"},
		{listen: "no-port", wantErr: true},
	}
	for _, tt := range tests {
		got, err := healthURL(tt.listen)
		if tt.wantErr {
			if err == nil {
				t.Errorf("healthURL(%q) = %q, want an error", tt.listen, got)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("healthURL(%q) = %q, %v; want %q", tt.listen, got, err, tt.want)
		}
	}
}

func TestProbe(t *testing.T) {
	tests := []struct {
		status  int
		healthy bool
	}{
		{http.StatusOK, true},
		{http.StatusUnauthorized, false},
		{http.StatusInternalServerError, false},
		{http.StatusNotFound, false},
	}
	for _, tt := range tests {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != healthPath {
				w.WriteHeader(http.StatusTeapot)
				return
			}
			w.WriteHeader(tt.status)
		}))
		err := probe(context.Background(), server.URL+healthPath)
		server.Close()
		if (err == nil) != tt.healthy {
			t.Errorf("status %d: probe = %v, want healthy %v", tt.status, err, tt.healthy)
		}
	}
}

func TestProbeFailsWithoutServer(t *testing.T) {
	if err := probe(context.Background(), "http://"+freeAddress(t)+healthPath); err == nil {
		t.Error("probe succeeded without a server")
	}
}

func TestHealthcheckCommandUsesTheConfiguredListenAddress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	listen := strings.TrimPrefix(server.URL, "http://")
	env := func(key string) string {
		if key == config.EnvListen {
			return listen
		}
		return ""
	}
	if err := run(context.Background(), []string{"healthcheck"}, env); err != nil {
		t.Errorf("healthcheck against a serving listener = %v", err)
	}
	down := func(key string) string {
		if key == config.EnvListen {
			return freeAddress(t)
		}
		return ""
	}
	if err := run(context.Background(), []string{"healthcheck"}, down); err == nil {
		t.Error("healthcheck succeeded without a server")
	}
}
