//go:build e2e

package e2e

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Admin account created through the setup endpoint.
const (
	adminUsername = "admin"
	adminPassword = "e2e-admin-password"
)

const (
	apiStartTimeout = 60 * time.Second
	pollInterval    = 500 * time.Millisecond
)

// tunnelDeck is one TunnelDeck container: its API and its network
// namespace, which plays the Docker host.
type tunnelDeck struct {
	stack   stack
	backend backend
	api     *apiClient
}

// attachTunnelDeck finds the published API port, waits for the API,
// creates the admin account on first use and signs in.
func attachTunnelDeck(t *testing.T, s stack, b backend) *tunnelDeck {
	t.Helper()
	td := &tunnelDeck{stack: s, backend: b}
	td.attach(t)
	return td
}

// attach (re)connects the API client; a restart loses the in-memory
// session and may change the published port.
func (td *tunnelDeck) attach(t *testing.T) {
	t.Helper()
	address := strings.TrimSpace(td.stack.compose(t, commandTimeout, "port", td.backend.service, "8194"))
	td.api = newAPIClient("http://" + address)
	var session struct {
		SetupRequired bool `json:"setupRequired"`
	}
	deadline := time.Now().Add(apiStartTimeout)
	for {
		err := td.api.get("/api/session", &session)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("API of %s not reachable: %v", td.backend.service, err)
		}
		time.Sleep(pollInterval)
	}
	credentials := map[string]string{"username": adminUsername, "password": adminPassword}
	if session.SetupRequired {
		td.must(t, td.api.call(http.MethodPost, "/api/setup", credentials, nil), "set up the admin account")
	}
	td.must(t, td.api.call(http.MethodPost, "/api/login", credentials, nil), "sign in")
}

func (td *tunnelDeck) must(t *testing.T, err error, action string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s on %s: %v", action, td.backend.service, err)
	}
}

// exec runs a command in TunnelDeck's container (its network namespace).
func (td *tunnelDeck) exec(t *testing.T, args ...string) string {
	t.Helper()
	return td.stack.exec(t, td.backend.service, args...)
}

func (td *tunnelDeck) restart(t *testing.T) {
	t.Helper()
	td.stack.compose(t, commandTimeout, "restart", td.backend.service)
	td.attach(t)
}

func (td *tunnelDeck) selfChecks(t *testing.T) []checkResult {
	t.Helper()
	var system struct {
		Checks []checkResult `json:"checks"`
	}
	td.must(t, td.api.get("/api/system", &system), "read the system status")
	return system.Checks
}

func (td *tunnelDeck) createProfile(t *testing.T, req profileRequest) string {
	t.Helper()
	var created struct {
		ID string `json:"id"`
	}
	td.must(t, td.api.call(http.MethodPost, "/api/profiles", req, &created), "create a profile")
	return created.ID
}

func (td *tunnelDeck) deleteProfile(t *testing.T, id string) {
	t.Helper()
	td.must(t, td.api.call(http.MethodDelete, "/api/profiles/"+id, nil, nil), "delete a profile")
}

func (td *tunnelDeck) connect(t *testing.T, profileID string) {
	t.Helper()
	body := map[string]string{"profileId": profileID}
	td.must(t, td.api.call(http.MethodPost, "/api/connection/connect", body, nil), "connect")
}

func (td *tunnelDeck) disconnect(t *testing.T) {
	t.Helper()
	td.must(t, td.api.call(http.MethodPost, "/api/connection/disconnect", nil, nil), "disconnect")
	td.waitForState(t, "disconnected", 30*time.Second)
}

func (td *tunnelDeck) status(t *testing.T) connectionStatus {
	t.Helper()
	var status connectionStatus
	td.must(t, td.api.get("/api/connection", &status), "read the connection status")
	return status
}

func (td *tunnelDeck) waitForState(t *testing.T, state string, timeout time.Duration) connectionStatus {
	t.Helper()
	return td.waitFor(t, "state "+state, timeout, func(s connectionStatus) bool { return s.State == state })
}

// waitFor polls the connection status until done accepts it. On timeout
// it fails with the last status and the newest log lines.
func (td *tunnelDeck) waitFor(t *testing.T, what string, timeout time.Duration, done func(connectionStatus) bool) connectionStatus {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		status := td.status(t)
		if done(status) {
			return status
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited %s for %s; last status %+v\nlog:\n%s", timeout, what, status, td.logTail())
		}
		time.Sleep(pollInterval)
	}
}

// logTail returns the newest lines of the connection log for diagnostics.
func (td *tunnelDeck) logTail() string {
	var logs struct {
		Lines []json.RawMessage `json:"lines"`
	}
	if err := td.api.get("/api/logs?tail=40", &logs); err != nil {
		return err.Error()
	}
	lines := make([]string, len(logs.Lines))
	for i, line := range logs.Lines {
		lines[i] = string(line)
	}
	return strings.Join(lines, "\n")
}

// logs returns every line of the connection log.
func (td *tunnelDeck) logs(t *testing.T) []logLine {
	t.Helper()
	var logs struct {
		Lines []logLine `json:"lines"`
	}
	td.must(t, td.api.get("/api/logs", &logs), "read the connection log")
	return logs.Lines
}

// hostAddress returns this device's LAN address as GET /api/firewall
// reports it.
func (td *tunnelDeck) hostAddress(t *testing.T) string {
	t.Helper()
	var state firewallState
	td.must(t, td.api.get("/api/firewall", &state), "read the firewall")
	if state.HostAddress == "" {
		t.Fatal("GET /api/firewall reports no host address")
	}
	return state.HostAddress
}

// setFirewallRules replaces the firewall rules and keeps every global
// protection on.
func (td *tunnelDeck) setFirewallRules(rules []firewallRule) error {
	settings := map[string]bool{"dropInvalid": true, "mssClamp": true, "synFloodProtection": true, "pingLimit": true}
	return td.api.call(http.MethodPut, "/api/firewall", map[string]any{"rules": rules, "settings": settings}, nil)
}

// setRemoteAccess switches the HTTPS listener with a self-signed
// certificate and waits until it follows the setting.
func (td *tunnelDeck) setRemoteAccess(t *testing.T, enabled bool, port int) {
	t.Helper()
	want := remoteAccess{Enabled: enabled, Port: port, CertificateSource: "selfSigned"}
	td.must(t, td.api.call(http.MethodPut, "/api/remote-access", want, nil), fmt.Sprintf("set remote access to %v", enabled))
	deadline := time.Now().Add(10 * time.Second)
	for {
		var got remoteAccess
		td.must(t, td.api.get("/api/remote-access", &got), "read remote access")
		if got.Listening == enabled {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("remote access listening = %v, want %v", got.Listening, enabled)
		}
		time.Sleep(pollInterval)
	}
}

// isValidationError reports whether err is a validation problem.
func isValidationError(err error) bool {
	var p *problem
	return errors.As(err, &p) && p.Code == "validation_failed"
}
