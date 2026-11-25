package api

import (
	"net/http"
	"testing"
)

func TestGetSystem(t *testing.T) {
	env := newTestEnv(t)
	rec := env.do(t, http.MethodGet, "/api/system", "")
	assertStatus(t, rec, http.StatusOK)
	got := decode[systemResponse](t, rec)
	want := systemResponse{
		Version: "1.2.3", ListenAddress: "192.168.1.10:8194", ServerTime: "2026-11-25T08:30:00Z", TimeZone: "Europe/Berlin",
	}
	if got.Version != want.Version || got.ListenAddress != want.ListenAddress ||
		got.ServerTime != want.ServerTime || got.TimeZone != want.TimeZone {
		t.Errorf("system = %+v, want %+v", got, want)
	}
	if len(got.Checks) != 1 || got.Checks[0].ID != "tun-device" || !got.Checks[0].OK {
		t.Errorf("checks = %+v", got.Checks)
	}
}

func TestGetSystemWithoutChecks(t *testing.T) {
	env := newTestEnv(t)
	env.server.deps.System.Checks = nil
	got := decode[map[string]any](t, env.do(t, http.MethodGet, "/api/system", ""))
	if checks, ok := got["checks"].([]any); !ok || len(checks) != 0 {
		t.Errorf("checks = %#v, want []", got["checks"])
	}
}
