package api

import (
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

type connectionJSON struct {
	State          domain.ConnectionState `json:"state"`
	ProfileID      string                 `json:"profileId"`
	Since          time.Time              `json:"since"`
	DataCipher     string                 `json:"dataCipher"`
	ControlChannel string                 `json:"controlChannel"`
	RoutingWarning *vpn.StatusError       `json:"routingWarning"`
	Advisories     []vpn.Advisory         `json:"advisories"`
}

func TestGetConnection(t *testing.T) {
	env := newTestEnv(t)
	assertStatus(t, env.do(t, http.MethodGet, "/api/connection", ""), http.StatusOK)
	idle := decode[connectionJSON](t, env.do(t, http.MethodGet, "/api/connection", ""))
	if idle.State != domain.StateDisconnected || idle.Advisories == nil || len(idle.Advisories) != 0 ||
		idle.DataCipher != "" || idle.ControlChannel != "" || idle.RoutingWarning != nil {
		t.Errorf("idle = %+v", idle)
	}

	stored := env.storedProfile("Office")
	since := time.Date(2026, 11, 25, 7, 0, 0, 0, time.UTC)
	warning := &vpn.StatusError{Code: domain.ErrorCodeRoutingFailed, Message: "applying the tunnel routing failed", Time: since}
	env.connection.setStatus(vpn.Status{State: domain.StateConnected, ProfileID: stored.ID, Since: since,
		DataCipher: "CHACHA20-POLY1305", ControlChannel: "TLSv1.3 TLS_CHACHA20_POLY1305_SHA256", RoutingWarning: warning})
	got := decode[connectionJSON](t, env.do(t, http.MethodGet, "/api/connection", ""))
	if got.State != domain.StateConnected || !got.Since.Equal(since) || len(got.Advisories) != 1 {
		t.Errorf("connected = %+v", got)
	}
	if got.DataCipher != "CHACHA20-POLY1305" || got.ControlChannel != "TLSv1.3 TLS_CHACHA20_POLY1305_SHA256" ||
		got.RoutingWarning == nil || *got.RoutingWarning != *warning {
		t.Errorf("negotiated channel and routing warning = %+v", got)
	}

	env.connection.setStatus(vpn.Status{State: domain.StateConnected, ProfileID: "deleted"})
	if got := decode[connectionJSON](t, env.do(t, http.MethodGet, "/api/connection", "")); len(got.Advisories) != 0 {
		t.Errorf("advisories of a missing profile = %+v", got.Advisories)
	}
}

func TestConnectionCommands(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		body       string
		commandErr error
		status     int
		code       string
		command    string
	}{
		{name: "connect", path: "/api/connection/connect", body: `{"profileId":"p1"}`, status: http.StatusAccepted, command: "connect p1"},
		{name: "connect without id", path: "/api/connection/connect", body: `{}`, status: http.StatusBadRequest, code: CodeBadRequest},
		{
			name: "connect unknown profile", path: "/api/connection/connect", body: `{"profileId":"x"}`,
			commandErr: fmt.Errorf("profile x: %w", domain.ErrNotFound), status: http.StatusNotFound, code: CodeNotFound, command: "connect x",
		},
		{name: "disconnect", path: "/api/connection/disconnect", status: http.StatusAccepted, command: "disconnect"},
		{name: "reconnect", path: "/api/connection/reconnect", status: http.StatusAccepted, command: "reconnect"},
		{
			name: "reconnect without wanted connection", path: "/api/connection/reconnect",
			commandErr: fmt.Errorf("nothing to reconnect: %w", domain.ErrConflict), status: http.StatusConflict, code: CodeConflict, command: "reconnect",
		},
		{
			name: "manager shut down", path: "/api/connection/disconnect",
			commandErr: vpn.ErrClosed, status: http.StatusServiceUnavailable, code: CodeUnavailable, command: "disconnect",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			env.connection.commandErr = tt.commandErr
			env.connection.setStatus(vpn.Status{State: domain.StateConnecting})
			rec := env.do(t, http.MethodPost, tt.path, tt.body)
			if tt.code != "" {
				assertProblem(t, rec, tt.status, tt.code)
			} else {
				assertStatus(t, rec, tt.status)
				if got := decode[connectionJSON](t, rec); got.State != domain.StateConnecting {
					t.Errorf("status = %+v", got)
				}
			}
			var want []string
			if tt.command != "" {
				want = []string{tt.command}
			}
			if !slices.Equal(env.connection.commands, want) {
				t.Errorf("commands = %v, want %v", env.connection.commands, want)
			}
		})
	}
}

func TestGetLogs(t *testing.T) {
	tests := []struct {
		query    string
		status   int
		wantTail int
	}{
		{query: "", status: http.StatusOK, wantTail: defaultLogTail},
		{query: "?tail=5", status: http.StatusOK, wantTail: 5},
		{query: "?tail=99999", status: http.StatusOK, wantTail: maxLogTail},
		{query: "?tail=0", status: http.StatusBadRequest},
		{query: "?tail=abc", status: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			env := newTestEnv(t)
			env.connection.logs = []domain.LogEvent{{Time: testNow, Level: domain.LogLevelInfo, Text: "Initialization Sequence Completed"}}
			rec := env.do(t, http.MethodGet, "/api/logs"+tt.query, "")
			if tt.status != http.StatusOK {
				assertProblem(t, rec, tt.status, CodeBadRequest)
				return
			}
			assertStatus(t, rec, tt.status)
			got := decode[logsResponse](t, rec)
			if len(got.Lines) != 1 || env.connection.logTail != tt.wantTail {
				t.Errorf("lines %+v, tail %d want %d", got.Lines, env.connection.logTail, tt.wantTail)
			}
		})
	}
}

func TestGetLogsEmpty(t *testing.T) {
	env := newTestEnv(t)
	got := decode[map[string]any](t, env.do(t, http.MethodGet, "/api/logs", ""))
	if lines, ok := got["lines"].([]any); !ok || len(lines) != 0 {
		t.Errorf("lines = %#v, want []", got["lines"])
	}
}
