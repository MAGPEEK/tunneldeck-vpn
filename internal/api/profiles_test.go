package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

type profileJSON struct {
	ID             string                        `json:"id"`
	Name           string                        `json:"name"`
	Protocol       domain.Protocol               `json:"protocol"`
	Settings       map[string]any                `json:"settings"`
	Secrets        map[string]domain.SecretState `json:"secrets"`
	DailyReconnect domain.DailyReconnect         `json:"dailyReconnect"`
	PublicAddress  string                        `json:"publicAddress"`
	Advisories     []vpn.Advisory                `json:"advisories"`
}

const validProfileBody = `{"name":"Office","protocol":"fakevpn","settings":{"host":"vpn.example.com"},` +
	`"secrets":{"password":"` + testSecret + `"},"dailyReconnect":{"enabled":true,"time":"03:15"}}`

func TestListDrivers(t *testing.T) {
	env := newTestEnv(t)
	rec := env.do(t, http.MethodGet, "/api/drivers", "")
	assertStatus(t, rec, http.StatusOK)
	got := decode[[]driverView](t, rec)
	if len(got) != 1 || got[0].Protocol != testProtocol || len(got[0].Schema.Sections) != 1 {
		t.Errorf("drivers = %+v", got)
	}
}

func TestListAndGetProfiles(t *testing.T) {
	env := newTestEnv(t)
	stored := env.storedProfile("Office")
	env.profiles.add(domain.Profile{Name: "Legacy", Protocol: "retired"})

	rec := env.do(t, http.MethodGet, "/api/profiles", "")
	assertStatus(t, rec, http.StatusOK)
	list := decode[[]profileJSON](t, rec)
	if len(list) != 2 || list[0].ID != stored.ID || !list[0].Secrets["password"].HasValue {
		t.Fatalf("list = %+v", list)
	}
	if len(list[0].Advisories) != 1 || list[0].Advisories[0].Code != "test_advice" {
		t.Errorf("advisories = %+v", list[0].Advisories)
	}
	if list[1].Advisories == nil || len(list[1].Advisories) != 0 {
		t.Errorf("unknown driver advisories = %#v, want []", list[1].Advisories)
	}

	rec = env.do(t, http.MethodGet, "/api/profiles/"+stored.ID, "")
	assertStatus(t, rec, http.StatusOK)
	if got := decode[profileJSON](t, rec); got.Name != "Office" || got.Settings["host"] != "vpn.example.com" {
		t.Errorf("profile = %+v", got)
	}
	assertProblem(t, env.do(t, http.MethodGet, "/api/profiles/missing", ""), http.StatusNotFound, CodeNotFound)
}

func TestListProfilesEmpty(t *testing.T) {
	env := newTestEnv(t)
	rec := env.do(t, http.MethodGet, "/api/profiles", "")
	if body := strings.TrimSpace(rec.Body.String()); body != "[]" {
		t.Errorf("body = %s, want []", body)
	}
}

func TestCreateProfile(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		status     int
		code       string
		wantFields []string
		wantPublic string
	}{
		{name: "valid", body: validProfileBody, status: http.StatusCreated},
		{
			name:   "default schedule",
			body:   `{"name":"Home","protocol":"fakevpn","settings":{"host":"h"},"secrets":{"password":"pw"}}`,
			status: http.StatusCreated,
		},
		{
			name:       "driver and domain fields together",
			body:       `{"name":"","protocol":"fakevpn","settings":{},"dailyReconnect":{"enabled":true,"time":"25:00"}}`,
			status:     http.StatusUnprocessableEntity,
			code:       CodeValidationFailed,
			wantFields: []string{"dailyReconnect.time", "host", "name", "password"},
		},
		{
			name:       "unknown protocol",
			body:       `{"name":"X","protocol":"ipsec"}`,
			status:     http.StatusUnprocessableEntity,
			code:       CodeValidationFailed,
			wantFields: []string{"protocol"},
		},
		{
			name: "missing protocol", body: `{"name":"X"}`,
			status: http.StatusUnprocessableEntity, code: CodeValidationFailed, wantFields: []string{"protocol"},
		},
		{
			name:   "public address",
			body:   `{"name":"Home","protocol":"fakevpn","settings":{"host":"h"},"secrets":{"password":"pw"},"publicAddress":" 203.0.113.10 "}`,
			status: http.StatusCreated, wantPublic: "203.0.113.10",
		},
		{
			name:   "invalid public address",
			body:   `{"name":"Home","protocol":"fakevpn","settings":{"host":"h"},"secrets":{"password":"pw"},"publicAddress":"2001:db8::1"}`,
			status: http.StatusUnprocessableEntity, code: CodeValidationFailed, wantFields: []string{"publicAddress"},
		},
		{name: "duplicate name", body: strings.Replace(validProfileBody, "Office", "taken", 1), status: http.StatusConflict, code: CodeConflict},
		{name: "unknown field", body: `{"name":"X","color":"red"}`, status: http.StatusBadRequest, code: CodeBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			env.storedProfile("Taken")
			rec := env.do(t, http.MethodPost, "/api/profiles", tt.body)
			if tt.code != "" {
				p := assertProblem(t, rec, tt.status, tt.code)
				fields := make([]string, 0, len(p.Fields))
				for field := range p.Fields {
					fields = append(fields, field)
				}
				slices.Sort(fields)
				if tt.wantFields != nil && !slices.Equal(fields, tt.wantFields) {
					t.Errorf("fields = %v, want %v", fields, tt.wantFields)
				}
				return
			}
			assertStatus(t, rec, tt.status)
			got := decode[profileJSON](t, rec)
			if got.ID == "" || !got.Secrets["password"].HasValue || len(got.Advisories) != 1 {
				t.Errorf("created = %+v", got)
			}
			if got.PublicAddress != tt.wantPublic {
				t.Errorf("publicAddress = %q, want %q", got.PublicAddress, tt.wantPublic)
			}
			if got.DailyReconnect.Time == "" {
				t.Errorf("daily reconnect time is empty")
			}
		})
	}
}

func TestCreateProfileStoreFailureIsGeneric(t *testing.T) {
	env := newTestEnv(t)
	env.profiles.failNext = errBoom
	p := assertProblem(t, env.do(t, http.MethodPost, "/api/profiles", validProfileBody), http.StatusInternalServerError, CodeInternal)
	if strings.Contains(p.Detail, "boom") {
		t.Errorf("detail leaks the error: %q", p.Detail)
	}
}

func TestUpdateProfile(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		status       int
		code         string
		wantPassword bool
	}{
		{
			name:   "keeps the stored secret",
			body:   `{"name":"Renamed","settings":{"host":"new.example.com"},"secrets":{"password":""}}`,
			status: http.StatusOK, wantPassword: true,
		},
		{
			name:   "replaces the secret",
			body:   `{"name":"Renamed","protocol":"fakevpn","settings":{"host":"h"},"secrets":{"password":"new"}}`,
			status: http.StatusOK, wantPassword: true,
		},
		{
			name:   "clearing a required secret fails validation",
			body:   `{"name":"Renamed","settings":{"host":"h"},"clearSecrets":["password"]}`,
			status: http.StatusUnprocessableEntity, code: CodeValidationFailed,
		},
		{
			name:   "protocol change",
			body:   `{"name":"Renamed","protocol":"other","settings":{"host":"h"}}`,
			status: http.StatusUnprocessableEntity, code: CodeValidationFailed,
		},
		{
			name:   "duplicate name",
			body:   `{"name":"other","settings":{"host":"h"}}`,
			status: http.StatusConflict, code: CodeConflict,
		},
		{name: "bad json", body: `[`, status: http.StatusBadRequest, code: CodeBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			stored := env.storedProfile("Office")
			env.storedProfile("Other")
			rec := env.do(t, http.MethodPut, "/api/profiles/"+stored.ID, tt.body)
			if tt.code != "" {
				assertProblem(t, rec, tt.status, tt.code)
				if len(env.connection.changed) != 0 {
					t.Errorf("ProfileChanged called after a failed update")
				}
				return
			}
			assertStatus(t, rec, tt.status)
			got := decode[profileJSON](t, rec)
			if got.Name != "Renamed" || got.Secrets["password"].HasValue != tt.wantPassword {
				t.Errorf("updated = %+v", got)
			}
			if !slices.Equal(env.connection.changed, []string{stored.ID}) {
				t.Errorf("ProfileChanged = %v, want [%s]", env.connection.changed, stored.ID)
			}
		})
	}
}

func TestUpdateMissingProfile(t *testing.T) {
	env := newTestEnv(t)
	assertProblem(t, env.do(t, http.MethodPut, "/api/profiles/missing", `{"name":"X"}`), http.StatusNotFound, CodeNotFound)
}

func TestDeleteProfile(t *testing.T) {
	tests := []struct {
		name         string
		state        domain.ConnectionState
		active       bool
		disconnect   disconnectMode
		wantCommands []string
	}{
		{name: "other profile active", state: domain.StateConnected},
		{name: "active but disconnected", state: domain.StateDisconnected, active: true, disconnect: stopsAtOnce, wantCommands: []string{"disconnect"}},
		{name: "active in error", state: domain.StateError, active: true, disconnect: stopsAtOnce, wantCommands: []string{"disconnect"}},
		{name: "active and connecting", state: domain.StateConnecting, active: true, disconnect: stopsAtOnce, wantCommands: []string{"disconnect"}},
		{name: "active and connected", state: domain.StateConnected, active: true, disconnect: stopsAtOnce, wantCommands: []string{"disconnect"}},
		{name: "active and reconnecting", state: domain.StateReconnecting, active: true, disconnect: stopsAtOnce, wantCommands: []string{"disconnect"}},
		{name: "active and disconnecting", state: domain.StateDisconnecting, active: true, disconnect: stopsAtOnce, wantCommands: []string{"disconnect"}},
		{
			name: "active and connected, stop reported by event", state: domain.StateConnected, active: true,
			disconnect: stopsByEvent, wantCommands: []string{"disconnect"},
		},
		{
			name: "active and reconnecting, stop reported by event", state: domain.StateReconnecting, active: true,
			disconnect: stopsByEvent, wantCommands: []string{"disconnect"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			stored := env.storedProfile("Office")
			status := vpn.Status{State: tt.state, ProfileID: "someone-else"}
			if tt.active {
				status.ProfileID = stored.ID
			}
			env.connection.setStatus(status)
			env.connection.disconnect = tt.disconnect
			rec := env.do(t, http.MethodDelete, "/api/profiles/"+stored.ID, "")
			assertStatus(t, rec, http.StatusNoContent)
			if !slices.Equal(env.connection.commands, tt.wantCommands) {
				t.Errorf("connection commands = %v, want %v", env.connection.commands, tt.wantCommands)
			}
			if len(env.profiles.ListProfiles()) != 0 || !slices.Equal(env.connection.changed, []string{stored.ID}) {
				t.Errorf("profiles %v, changed %v", env.profiles.ListProfiles(), env.connection.changed)
			}
		})
	}
	env := newTestEnv(t)
	assertProblem(t, env.do(t, http.MethodDelete, "/api/profiles/missing", ""), http.StatusNotFound, CodeNotFound)
}

func TestDeleteProfileKeepsProfileWhenTunnelDoesNotStop(t *testing.T) {
	env := newTestEnv(t)
	env.server = New(env.server.deps, Options{DisconnectTimeout: 20 * time.Millisecond})
	stored := env.storedProfile("Office")
	env.connection.setStatus(vpn.Status{State: domain.StateReconnecting, ProfileID: stored.ID})
	env.connection.disconnect = neverStops
	p := assertProblem(t, env.do(t, http.MethodDelete, "/api/profiles/"+stored.ID, ""), http.StatusServiceUnavailable, CodeUnavailable)
	if !strings.Contains(p.Detail, "did not stop in time") {
		t.Errorf("detail = %q", p.Detail)
	}
	if len(env.profiles.ListProfiles()) != 1 || len(env.connection.changed) != 0 {
		t.Errorf("profiles %v, changed %v; want the profile kept", env.profiles.ListProfiles(), env.connection.changed)
	}
	if env.connection.cancelCount() != 1 {
		t.Errorf("unsubscribed %d times, want 1", env.connection.cancelCount())
	}
}

func TestDeleteProfileKeepsProfileWhenDisconnectFails(t *testing.T) {
	env := newTestEnv(t)
	stored := env.storedProfile("Office")
	env.connection.setStatus(vpn.Status{State: domain.StateError, ProfileID: stored.ID})
	env.connection.commandErr = fmt.Errorf("manager stopped: %w", domain.ErrConflict)
	assertProblem(t, env.do(t, http.MethodDelete, "/api/profiles/"+stored.ID, ""), http.StatusConflict, CodeConflict)
	if len(env.profiles.ListProfiles()) != 1 || len(env.connection.changed) != 0 {
		t.Errorf("profiles %v, changed %v; want the profile kept", env.profiles.ListProfiles(), env.connection.changed)
	}
}

func TestImportProfile(t *testing.T) {
	env := newTestEnv(t)
	rec := env.do(t, http.MethodPost, "/api/profiles/import", `{"protocol":"fakevpn","text":"client\nremote x"}`)
	assertStatus(t, rec, http.StatusOK)
	var got struct {
		Settings map[string]any    `json:"settings"`
		Secrets  map[string]string `json:"secrets"`
		Warnings []ImportWarning   `json:"warnings"`
		Missing  []string          `json:"missing"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Settings["host"] != "vpn.example.com" || got.Secrets["password"] != testSecret || len(got.Warnings) != 2 ||
		got.Warnings[1].File != "ca.crt" || len(got.Missing) != 1 || got.Missing[0] != "username" {
		t.Errorf("draft = %+v", got)
	}

	p := assertProblem(t, env.do(t, http.MethodPost, "/api/profiles/import", `{"protocol":"ipsec","text":"x"}`),
		http.StatusUnprocessableEntity, CodeValidationFailed)
	if p.Fields["protocol"] == "" {
		t.Errorf("fields = %v", p.Fields)
	}
	assertProblem(t, env.do(t, http.MethodPost, "/api/profiles/import", `{"protocol":"fakevpn","text":""}`),
		http.StatusUnprocessableEntity, CodeValidationFailed)
}

func TestGenerateKeyPair(t *testing.T) {
	env := newTestEnv(t)
	if err := env.drivers.Register(keyProtocol, func() vpn.Driver { return fakeKeyDriver{} }); err != nil {
		t.Fatal(err)
	}

	rec := env.do(t, http.MethodPost, "/api/drivers/fakekeys/keypair", "")
	assertStatus(t, rec, http.StatusOK)
	if got := decode[keyPairView](t, rec); got.PrivateKey != "generated-private" || got.PublicKey != "generated-public" {
		t.Errorf("key pair = %+v", got)
	}
	if len(env.profiles.ListProfiles()) != 0 {
		t.Error("generating a key pair stored something")
	}

	assertProblem(t, env.do(t, http.MethodPost, "/api/drivers/fakevpn/keypair", ""), http.StatusNotFound, CodeNotFound)
	assertProblem(t, env.do(t, http.MethodPost, "/api/drivers/unknown/keypair", ""), http.StatusNotFound, CodeNotFound)
	assertStatus(t, env.do(t, http.MethodPost, "/api/drivers/fakekeys/keypair", "", withoutCSRF), http.StatusForbidden)
}

func TestProfileViewCarriesDerivedValues(t *testing.T) {
	env := newTestEnv(t)
	if err := env.drivers.Register(keyProtocol, func() vpn.Driver { return fakeKeyDriver{} }); err != nil {
		t.Fatal(err)
	}
	withKey := env.profiles.add(domain.Profile{
		Name: "Keyed", Protocol: keyProtocol, Secrets: map[string]string{"privateKey": testSecret},
	})
	env.storedProfile("Office")

	rec := env.do(t, http.MethodGet, "/api/profiles", "")
	assertStatus(t, rec, http.StatusOK)
	assertNoSecret(t, "/api/profiles", rec.Body.String())
	type derivedJSON struct {
		ID      string            `json:"id"`
		Derived map[string]string `json:"derived"`
	}
	list := decode[[]derivedJSON](t, rec)
	if len(list) != 2 || list[0].Derived["publicKey"] != "derived-public" || list[1].Derived != nil {
		t.Errorf("list = %+v", list)
	}

	rec = env.do(t, http.MethodPut, "/api/profiles/"+withKey.ID, `{"name":"Keyed","settings":{}}`)
	assertStatus(t, rec, http.StatusOK)
	if got := decode[derivedJSON](t, rec); got.Derived["publicKey"] != "derived-public" {
		t.Errorf("update = %+v, want the derived key of the kept secret", got)
	}

	rec = env.do(t, http.MethodPost, "/api/profiles", `{"name":"New","protocol":"fakekeys","settings":{},"secrets":{"privateKey":"typed"}}`)
	assertStatus(t, rec, http.StatusCreated)
	if got := decode[derivedJSON](t, rec); got.Derived["publicKey"] != "derived-public" {
		t.Errorf("create = %+v", got)
	}
}
