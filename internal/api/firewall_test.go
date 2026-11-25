package api

import (
	"net/http"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
)

const allSettings = `{"dropInvalid":true,"mssClamp":true,"synFloodProtection":true,"pingLimit":true}`

// firewallBody is a PUT body with every protection on and rules.
func firewallBody(rules ...string) string {
	return `{"rules":[` + strings.Join(rules, ",") + `],"settings":` + allSettings + `}`
}

// Rules as the UI sends them.
const (
	sshRule      = `{"name":"SSH","direction":"inbound","protocol":"tcp","destination":{"kind":"host"},"destinationPort":{"from":22},"enabled":true}`
	ikeForward   = `{"name":"IKE","direction":"inbound","protocol":"udp","destination":{"kind":"address","cidr":"192.168.2.2"},"destinationPort":{"from":500},"keepSourceAddress":true,"enabled":true}`
	lancomOutput = `{"name":"LANCOM out","direction":"outbound","protocol":"any","source":"192.168.2.2","destination":{"kind":"address","cidr":"0.0.0.0/0"},"enabled":true}`
)

func TestGetFirewall(t *testing.T) {
	env := newTestEnv(t)
	body := strings.TrimSpace(env.do(t, http.MethodGet, "/api/firewall", "").Body.String())
	want := `{"rules":[],"settings":{"dropInvalid":false,"mssClamp":false,"synFloodProtection":false,"pingLimit":false},` +
		`"hostAddress":"192.168.2.10","lanSubnets":["192.168.2.0/24"],"ipForward":true}`
	if body != want {
		t.Errorf("body = %s\nwant %s", body, want)
	}

	env.firewallStore.firewall = domain.Firewall{FirewallSettings: domain.DefaultFirewallSettings(), Rules: []domain.FirewallRule{hostPortRule("r1", domain.ProtocolTCP, 22)}}
	rec := env.do(t, http.MethodGet, "/api/firewall", "")
	assertStatus(t, rec, http.StatusOK)
	got := decode[firewallResponse](t, rec)
	if len(got.Rules) != 1 || got.Rules[0].ID != "r1" || got.Settings != domain.DefaultFirewallSettings() {
		t.Errorf("response = %+v", got)
	}
}

func TestGetFirewallWithoutNetworkDetection(t *testing.T) {
	env := newTestEnv(t)
	env.firewall.networkErr = errBoom
	rec := env.do(t, http.MethodGet, "/api/firewall", "")
	assertStatus(t, rec, http.StatusOK)
	body := rec.Body.String()
	if !strings.Contains(body, `"hostAddress":"","lanSubnets":[],"ipForward":false`) || strings.Contains(body, "boom") {
		t.Errorf("body = %s, want empty network values and no error", body)
	}
}

func TestPutFirewall(t *testing.T) {
	env := newTestEnv(t)
	body := `{"rules":[` + sshRule + `,` + ikeForward + `,` + lancomOutput + `],` +
		`"settings":{"dropInvalid":true,"mssClamp":false,"synFloodProtection":true,"pingLimit":false}}`
	rec := env.do(t, http.MethodPut, "/api/firewall", body)
	assertStatus(t, rec, http.StatusOK)
	got := decode[firewallResponse](t, rec)
	wantSettings := domain.FirewallSettings{DropInvalid: true, SYNFloodProtection: true}
	if len(got.Rules) != 3 || got.Settings != wantSettings || got.HostAddress != "192.168.2.10" || !got.IPForward {
		t.Fatalf("response = %+v", got)
	}
	for _, rule := range got.Rules {
		if rule.ID == "" {
			t.Errorf("rule without ID: %+v", rule)
		}
	}
	if !got.Rules[1].KeepSourceAddress || got.Rules[1].Destination.CIDR != "192.168.2.2" || got.Rules[2].Direction != domain.DirectionOutbound {
		t.Errorf("rules = %+v", got.Rules)
	}
	stored := env.firewallStore.Firewall()
	if stored.FirewallSettings != wantSettings || len(stored.Rules) != 3 {
		t.Errorf("stored = %+v", stored)
	}
	installs := env.firewall.installs()
	if len(installs) != 1 || len(installs[0].Rules) != 3 || env.firewall.uiPort != testUIPort {
		t.Fatalf("installs = %+v, ui port %d", installs, env.firewall.uiPort)
	}

	rec = env.do(t, http.MethodPut, "/api/firewall", `{"rules":null,"settings":`+allSettings+`}`)
	assertStatus(t, rec, http.StatusOK)
	if got := decode[firewallResponse](t, rec); got.Rules == nil || len(got.Rules) != 0 {
		t.Errorf("rules after clearing = %v, want []", got.Rules)
	}
}

func TestPutFirewallRejects(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		prepare    func(*testEnv)
		status     int
		code       string
		wantFields []string
	}{
		{
			name: "settings missing", body: `{"rules":[]}`,
			wantFields: []string{"settings.dropInvalid", "settings.mssClamp", "settings.synFloodProtection", "settings.pingLimit"},
		},
		{name: "one setting missing", body: `{"rules":[],"settings":{"dropInvalid":true,"mssClamp":true,"synFloodProtection":true}}`, wantFields: []string{"settings.pingLimit"}},
		{name: "rule without name", body: firewallBody(strings.Replace(sshRule, `"SSH"`, `""`, 1)), wantFields: []string{"rules[0].name"}},
		{name: "unknown protocol", body: firewallBody(strings.Replace(sshRule, `"tcp"`, `"sctp"`, 1)), wantFields: []string{"rules[0].protocol"}},
		{name: "unknown direction", body: firewallBody(strings.Replace(sshRule, `"inbound"`, `"sideways"`, 1)), wantFields: []string{"rules[0].direction"}},
		{name: "outbound without source", body: firewallBody(strings.Replace(lancomOutput, `"source":"192.168.2.2",`, ``, 1)), wantFields: []string{"rules[0].source"}},
		{name: "range too long", body: firewallBody(strings.Replace(sshRule, `{"from":22}`, `{"from":1000,"to":3000}`, 1)), wantFields: []string{"rules[0].destinationPort"}},
		{name: "duplicate rule", body: firewallBody(sshRule, sshRule), wantFields: []string{"rules[1].name"}},
		{
			name:       "public address conflict",
			body:       firewallBody(ikeForward, strings.Replace(ikeForward, "192.168.2.2", "192.168.2.3", 1)),
			wantFields: []string{"rules[1].destinationPort"},
		},
		{name: "web UI port", body: firewallBody(strings.Replace(sshRule, `{"from":22}`, `{"from":8194}`, 1)), wantFields: []string{"rules[0].destinationPort"}},
		{
			name: "remote-access port", body: firewallBody(strings.Replace(sshRule, `{"from":22}`, `{"from":8443}`, 1)),
			prepare: func(e *testEnv) {
				e.remote.settings = domain.RemoteAccess{Enabled: true, Port: 8443, CertificateSource: domain.CertificateSelfSigned}
			},
			wantFields: []string{"rules[0].destinationPort"},
		},
		{name: "destination outside the LAN", body: firewallBody(strings.Replace(ikeForward, "192.168.2.2", "10.0.0.2", 1)), wantFields: []string{"rules[0].destination"}},
		{
			name: "LAN not detected", body: firewallBody(ikeForward),
			prepare:    func(e *testEnv) { e.firewall.networkErr = errBoom },
			wantFields: []string{"rules[0].destination"},
		},
		{name: "unknown rule field", body: firewallBody(strings.Replace(sshRule, `"enabled"`, `"x":1,"enabled"`, 1)), status: http.StatusBadRequest, code: CodeBadRequest},
		{name: "wrong type", body: `{"rules":[],"settings":{"dropInvalid":"yes"}}`, status: http.StatusBadRequest, code: CodeBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			if tt.prepare != nil {
				tt.prepare(env)
			}
			status, code := tt.status, tt.code
			if code == "" {
				status, code = http.StatusUnprocessableEntity, CodeValidationFailed
			}
			p := assertProblem(t, env.do(t, http.MethodPut, "/api/firewall", tt.body), status, code)
			for _, field := range tt.wantFields {
				if p.Fields[field] == "" {
					t.Errorf("fields = %v, want %s", p.Fields, field)
				}
			}
			if len(env.firewall.installs()) != 0 || len(env.firewallStore.Firewall().Rules) != 0 {
				t.Error("an invalid request was stored or applied")
			}
		})
	}
}

func TestPutFirewallRollsBackWhenApplyFails(t *testing.T) {
	env := newTestEnv(t)
	previous := domain.Firewall{FirewallSettings: domain.DefaultFirewallSettings(), Rules: []domain.FirewallRule{hostPortRule("old", domain.ProtocolTCP, 22)}}
	env.firewallStore.firewall = previous
	env.firewall.failOnce = errBoom
	rec := env.do(t, http.MethodPut, "/api/firewall", firewallBody(ikeForward))
	p := assertProblem(t, rec, http.StatusInternalServerError, CodeFirewallFailed)
	if !strings.Contains(p.Detail, "previous configuration was restored") || !strings.Contains(p.Detail, errBoom.Error()) {
		t.Errorf("detail = %q", p.Detail)
	}
	if got := env.firewallStore.Firewall(); len(got.Rules) != 1 || got.Rules[0].ID != "old" || got.FirewallSettings != previous.FirewallSettings {
		t.Errorf("stored after rollback = %+v, want the previous configuration", got)
	}
	installs := env.firewall.installs()
	if len(installs) != 2 || installs[0].Rules[0].Name != "IKE" || installs[1].Rules[0].ID != "old" {
		t.Fatalf("installs = %+v, want the new and then the previous configuration", installs)
	}
}

func TestPutFirewallStoreFailure(t *testing.T) {
	env := newTestEnv(t)
	env.firewallStore.failSet = errBoom
	p := assertProblem(t, env.do(t, http.MethodPut, "/api/firewall", firewallBody(sshRule)), http.StatusInternalServerError, CodeInternal)
	if strings.Contains(p.Detail, "boom") {
		t.Errorf("detail leaks the error: %q", p.Detail)
	}
	if len(env.firewall.installs()) != 0 {
		t.Error("firewall applied after the store failed")
	}
}

func TestHostAccessIsGone(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		for name, opts := range map[string][]requestOption{"signed in": nil, "anonymous": {anonymous}} {
			t.Run(method+" "+name, func(t *testing.T) {
				env := newTestEnv(t)
				p := assertProblem(t, env.do(t, method, "/api/host-access", `{"rules":[]}`, opts...), http.StatusGone, CodeGone)
				if !strings.Contains(p.Detail, "/api/firewall") {
					t.Errorf("detail = %q, want a pointer to /api/firewall", p.Detail)
				}
				if len(env.firewall.installs()) != 0 {
					t.Error("firewall applied")
				}
			})
		}
	}
}

func TestIPsecTemplate(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantRules int
		wantPeer  string
	}{
		{name: "no peers", body: `{"name":"LANCOM","deviceAddress":"192.168.2.2"}`, wantRules: 5},
		{name: "empty peers", body: `{"name":"LANCOM","deviceAddress":"192.168.2.2","peers":[]}`, wantRules: 5},
		{name: "two peers", body: `{"name":" LANCOM ","deviceAddress":"192.168.2.2","peers":["203.0.113.7","198.51.100.0/24"]}`, wantRules: 10, wantPeer: "203.0.113.7/32"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			rec := env.do(t, http.MethodPost, "/api/firewall/templates/ipsec", tt.body)
			assertStatus(t, rec, http.StatusOK)
			got := decode[rulesResponse](t, rec).Rules
			if len(got) != tt.wantRules {
				t.Fatalf("got %d rules, want %d: %+v", len(got), tt.wantRules, got)
			}
			first := got[0]
			if first.Name != "LANCOM: IKE" || first.Destination.CIDR != "192.168.2.2" || first.Source != tt.wantPeer || first.ID != "" {
				t.Errorf("first rule = %+v", first)
			}
			if err := domain.ValidateFirewallRules(got); err != nil {
				t.Errorf("template rules are invalid: %v", err)
			}
			if len(env.firewall.installs()) != 0 || len(env.firewallStore.Firewall().Rules) != 0 {
				t.Error("the template was stored or applied")
			}
		})
	}
}

func TestIPsecTemplateRejects(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		status     int
		code       string
		wantFields []string
	}{
		{name: "everything missing", body: `{}`, wantFields: []string{"name", "deviceAddress"}},
		{name: "name too long", body: `{"name":"` + strings.Repeat("n", domain.MaxIPsecTemplateNameLength+1) + `","deviceAddress":"192.168.2.2"}`, wantFields: []string{"name"}},
		{name: "device is a network", body: `{"name":"x","deviceAddress":"192.168.2.0/24"}`, wantFields: []string{"deviceAddress"}},
		{name: "device outside the LAN", body: `{"name":"x","deviceAddress":"10.0.0.2"}`, wantFields: []string{"deviceAddress"}},
		{name: "bad peer", body: `{"name":"x","deviceAddress":"192.168.2.2","peers":["203.0.113.7","nope"]}`, wantFields: []string{"peers[1]"}},
		{name: "unknown field", body: `{"name":"x","deviceAddress":"192.168.2.2","psk":"x"}`, status: http.StatusBadRequest, code: CodeBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			status, code := tt.status, tt.code
			if code == "" {
				status, code = http.StatusUnprocessableEntity, CodeValidationFailed
			}
			p := assertProblem(t, env.do(t, http.MethodPost, "/api/firewall/templates/ipsec", tt.body), status, code)
			for _, field := range tt.wantFields {
				if p.Fields[field] == "" {
					t.Errorf("fields = %v, want %s", p.Fields, field)
				}
			}
		})
	}
}
