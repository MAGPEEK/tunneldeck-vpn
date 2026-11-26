package api

import (
	"net/http"
	"testing"
	"time"
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

func TestGetSystemSendsDetailCodeParamsAndDetail(t *testing.T) {
	env := newTestEnv(t)
	got := decode[map[string]any](t, env.do(t, http.MethodGet, "/api/system", ""))
	checks, _ := got["checks"].([]any)
	if len(checks) != 1 {
		t.Fatalf("checks = %#v", got["checks"])
	}
	check, _ := checks[0].(map[string]any)
	params, _ := check["params"].(map[string]any)
	if check["detailCode"] != "tunPresent" || params["path"] != "/dev/net/tun" || check["detail"] != "present" {
		t.Errorf("check = %#v, want detailCode, params and the English detail", check)
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

func TestGetSystemStartedAt(t *testing.T) {
	env := newTestEnv(t)
	env.server.deps.System.StartedAt = time.Date(2026, 11, 20, 6, 0, 0, 0, time.FixedZone("CET", 3600))
	got := decode[map[string]any](t, env.do(t, http.MethodGet, "/api/system", ""))
	if got["startedAt"] != "2026-11-20T05:00:00Z" {
		t.Errorf("startedAt = %v, want RFC 3339 UTC", got["startedAt"])
	}
	if _, present := got["hostUptimeSeconds"]; present {
		t.Error("hostUptimeSeconds is present, want it gone")
	}
}
