package api

import (
	"net/http"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
)

func TestGetHostAccess(t *testing.T) {
	env := newTestEnv(t)
	if body := strings.TrimSpace(env.do(t, http.MethodGet, "/api/host-access", "").Body.String()); body != `{"rules":[]}` {
		t.Errorf("empty body = %s", body)
	}
	env.hostAccess.setHostRules(domain.HostAccessRule{ID: "r1", Protocol: domain.TransportTCP, Port: 22, Enabled: true})
	rec := env.do(t, http.MethodGet, "/api/host-access", "")
	assertStatus(t, rec, http.StatusOK)
	if got := decode[hostAccessBody](t, rec); len(got.Rules) != 1 || got.Rules[0].Port != 22 {
		t.Errorf("rules = %+v", got.Rules)
	}
}

func TestPutHostAccess(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		status    int
		code      string
		wantField string
	}{
		{name: "valid", body: `{"rules":[{"protocol":"tcp","port":22,"sourceCidr":"10.8.0.0/24","enabled":true,"comment":"ssh"}]}`, status: http.StatusOK},
		{name: "empty list", body: `{"rules":[]}`, status: http.StatusOK},
		{name: "ui port tcp", body: `{"rules":[{"protocol":"tcp","port":8194,"enabled":true}]}`, status: http.StatusUnprocessableEntity, code: CodeValidationFailed, wantField: "rules[0].port"},
		{name: "ui port udp", body: `{"rules":[{"protocol":"udp","port":8194,"enabled":false}]}`, status: http.StatusUnprocessableEntity, code: CodeValidationFailed, wantField: "rules[0].port"},
		{name: "bad protocol", body: `{"rules":[{"protocol":"icmp","port":1}]}`, status: http.StatusUnprocessableEntity, code: CodeValidationFailed, wantField: "rules[0].protocol"},
		{name: "unknown field", body: `{"rules":[],"x":1}`, status: http.StatusBadRequest, code: CodeBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			rec := env.do(t, http.MethodPut, "/api/host-access", tt.body)
			if tt.code != "" {
				p := assertProblem(t, rec, tt.status, tt.code)
				if tt.wantField != "" && p.Fields[tt.wantField] == "" {
					t.Errorf("fields = %v, want %s", p.Fields, tt.wantField)
				}
				if len(env.firewall.applied) != 0 {
					t.Error("firewall applied for an invalid request")
				}
				return
			}
			assertStatus(t, rec, tt.status)
			got := decode[hostAccessBody](t, rec)
			if len(env.firewall.applied) != 1 || env.firewall.uiPort != testUIPort {
				t.Fatalf("firewall calls %v, ui port %d", env.firewall.applied, env.firewall.uiPort)
			}
			for _, rule := range got.Rules {
				if rule.ID == "" {
					t.Errorf("rule without ID: %+v", rule)
				}
			}
		})
	}
}

func TestPutHostAccessRollsBackWhenTheFirewallFails(t *testing.T) {
	env := newTestEnv(t)
	env.hostAccess.setHostRules(domain.HostAccessRule{ID: "old", Protocol: domain.TransportTCP, Port: 22, Enabled: true})
	env.firewall.err = errBoom
	rec := env.do(t, http.MethodPut, "/api/host-access", `{"rules":[{"protocol":"udp","port":53,"enabled":true}]}`)
	p := assertProblem(t, rec, http.StatusInternalServerError, CodeFirewallFailed)
	if strings.Contains(p.Detail, "boom") {
		t.Errorf("detail leaks the error: %q", p.Detail)
	}
	if got := env.hostAccess.Firewall().Rules; len(got) != 1 || got[0].ID != "old" {
		t.Errorf("rules after rollback = %+v, want the previous rules", got)
	}
}

func TestHostAccessKeepsOtherFirewallRules(t *testing.T) {
	env := newTestEnv(t)
	outbound := domain.FirewallRule{
		ID: "out", Name: "LANCOM", Direction: domain.DirectionOutbound, Protocol: domain.ProtocolAny,
		Source: "192.168.2.2", Destination: domain.FirewallDestination{Kind: domain.DestinationAddress, CIDR: "0.0.0.0/0"}, Enabled: true,
	}
	ssh := domain.HostAccessRule{ID: "ssh", Protocol: domain.TransportTCP, Port: 22, Enabled: true}.FirewallRule()
	env.hostAccess.setRules(outbound, ssh)

	got := decode[hostAccessBody](t, env.do(t, http.MethodGet, "/api/host-access", ""))
	if len(got.Rules) != 1 || got.Rules[0].ID != "ssh" {
		t.Fatalf("GET rules = %+v, want only the host rule", got.Rules)
	}
	rec := env.do(t, http.MethodPut, "/api/host-access", `{"rules":[{"protocol":"udp","port":53,"enabled":true}]}`)
	assertStatus(t, rec, http.StatusOK)
	stored := env.hostAccess.Firewall().Rules
	if len(stored) != 2 || stored[0].Name != "Host port 53/udp" || stored[1].ID != "out" {
		t.Fatalf("stored rules = %+v, want the new host rule, then the outbound rule", stored)
	}
	if applied := env.firewall.applied; len(applied) != 1 || len(applied[0].Rules) != 2 {
		t.Fatalf("applied = %+v", applied)
	}
}

func TestPutHostAccessStoreFailure(t *testing.T) {
	env := newTestEnv(t)
	env.hostAccess.failSet = errBoom
	assertProblem(t, env.do(t, http.MethodPut, "/api/host-access", `{"rules":[]}`), http.StatusInternalServerError, CodeInternal)
	if len(env.firewall.applied) != 0 {
		t.Error("firewall applied after the store failed")
	}
}
