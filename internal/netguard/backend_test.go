package netguard

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// Version lines as printed by iptables -V.
const (
	nftVersion    = "iptables v1.8.13 (nf_tables)\n"
	legacyVersion = "iptables v1.8.13 (legacy)\n"
)

// Listings of iptables -S with the number of host rules they hold.
const (
	// emptyFilter holds only ACCEPT policies: 0 host rules.
	emptyFilter = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n"
	// ownChainsOnly holds only TunnelDeck's chains and jumps: 0 host rules.
	ownChainsOnly = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n" +
		"-N TUNNELDECK-INPUT\n-N TUNNELDECK-PROBE\n" +
		"-A INPUT -i tdvpn0 -j TUNNELDECK-INPUT\n" +
		"-A TUNNELDECK-INPUT -j DROP\n"
	// ufwFilter: two DROP policies and two rules, 4 host rules.
	ufwFilter = "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n" +
		"-N ufw-before-input\n" +
		"-A INPUT -j ufw-before-input\n" +
		"-A ufw-before-input -i lo -j ACCEPT\n"
	// dockerDNSNat: Docker's embedded DNS in a container, 2 host rules.
	dockerDNSNat = "# Warning: iptables-legacy tables present, use iptables-legacy to see them\n" +
		"-P PREROUTING ACCEPT\n-P INPUT ACCEPT\n-P OUTPUT ACCEPT\n-P POSTROUTING ACCEPT\n" +
		"-N DOCKER_OUTPUT\n" +
		"-A OUTPUT -d 127.0.0.11/32 -j DOCKER_OUTPUT\n" +
		"-A DOCKER_OUTPUT -d 127.0.0.11/32 -p udp -m udp --dport 53 -j DNAT --to-destination 127.0.0.11:60575\n"
)

// Detection commands in the order netguard runs them.
const (
	nftFilter    = "iptables-nft -w -t filter -S"
	nftNat       = "iptables-nft -w -t nat -S"
	legacyFilter = "iptables-legacy -w -t filter -S"
	legacyNat    = "iptables-legacy -w -t nat -S"
	plainVersion = "iptables -V"
	plainFilter  = "iptables -w -t filter -S"
	plainNat     = "iptables -w -t nat -S"
)

func notFound() fakeResult {
	return fakeResult{err: &CommandError{ExitCode: -1, Err: exec.ErrNotFound}}
}

func TestBackendDetection(t *testing.T) {
	tests := []struct {
		name       string
		preference BackendPreference
		script     func(*fakeRunner)
		wantCalls  []string
		want       Backend
	}{
		{
			name: "only legacy works",
			script: func(f *fakeRunner) {
				f.on(nftFilter, notFound()).on(plainVersion, notFound()).on(legacyFilter, ok(ufwFilter))
			},
			wantCalls: []string{nftFilter, legacyFilter, legacyNat, plainVersion},
			want:      Backend{Binary: "iptables-legacy", Reason: "only the legacy backend works"},
		},
		{
			name: "only nft works",
			script: func(f *fakeRunner) {
				f.on(legacyFilter, fail(noPermission)).on(plainVersion, ok(nftVersion))
			},
			wantCalls: []string{nftFilter, nftNat, legacyFilter, plainVersion},
			want:      Backend{Binary: "iptables-nft", Reason: "only the nf_tables backend works"},
		},
		{
			name: "both work, host rules only in legacy",
			script: func(f *fakeRunner) {
				f.on(nftFilter, ok(ownChainsOnly)).on(legacyFilter, ok(ufwFilter))
			},
			wantCalls: []string{nftFilter, nftNat, legacyFilter, legacyNat},
			want:      Backend{Binary: "iptables-legacy", Reason: "host rules only in legacy (4)"},
		},
		{
			name: "both work, host rules only in nft",
			script: func(f *fakeRunner) {
				f.on(nftNat, ok(dockerDNSNat)).on(legacyFilter, ok(ownChainsOnly))
			},
			wantCalls: []string{nftFilter, nftNat, legacyFilter, legacyNat},
			want:      Backend{Binary: "iptables-nft", Reason: "host rules only in nf_tables (2)"},
		},
		{
			name: "both hold host rules, legacy more",
			script: func(f *fakeRunner) {
				f.on(nftNat, ok(dockerDNSNat)).on(legacyFilter, ok(ufwFilter))
			},
			wantCalls: []string{nftFilter, nftNat, legacyFilter, legacyNat},
			want: Backend{
				Binary: "iptables-legacy",
				Reason: "host rules in both backends (nf_tables 2, legacy 4), chose legacy; the other backend's rules still apply",
				Mixed:  true,
			},
		},
		{
			name: "both hold as many host rules, nft wins",
			script: func(f *fakeRunner) {
				f.on(nftFilter, ok(ufwFilter)).on(legacyFilter, ok(ufwFilter))
			},
			wantCalls: []string{nftFilter, nftNat, legacyFilter, legacyNat},
			want: Backend{
				Binary: "iptables-nft",
				Reason: "host rules in both backends (nf_tables 4, legacy 4), chose nf_tables; the other backend's rules still apply",
				Mixed:  true,
			},
		},
		{
			name: "neither holds host rules, a missing nat table counts as empty",
			script: func(f *fakeRunner) {
				f.on(nftFilter, ok(emptyFilter)).on(legacyFilter, ok(ownChainsOnly)).
					on(legacyNat, fail("iptables v1.8.13 (legacy): can't initialize iptables table `nat': Table does not exist"))
			},
			wantCalls: []string{nftFilter, nftNat, legacyFilter, legacyNat},
			want:      Backend{Binary: "iptables-nft", Reason: "no host rules in either backend, nf_tables preferred"},
		},
		{
			name: "plain iptables stands in for a missing iptables-nft",
			script: func(f *fakeRunner) {
				f.on(nftFilter, notFound()).on(plainVersion, ok(nftVersion)).on(plainFilter, ok(ufwFilter))
			},
			wantCalls: []string{nftFilter, legacyFilter, legacyNat, plainVersion, plainFilter, plainNat},
			want:      Backend{Binary: "iptables", Reason: "host rules only in nf_tables (4)"},
		},
		{
			name: "plain iptables stands in for a missing iptables-legacy",
			script: func(f *fakeRunner) {
				f.on(legacyFilter, notFound()).on(plainVersion, ok(legacyVersion)).on(plainFilter, ok(ufwFilter))
			},
			wantCalls: []string{nftFilter, nftNat, legacyFilter, plainVersion, plainFilter, plainNat},
			want:      Backend{Binary: "iptables", Reason: "host rules only in legacy (4)"},
		},
		{
			name:       "forced nft ignores legacy rules",
			preference: BackendNft,
			script: func(f *fakeRunner) {
				f.on(legacyFilter, ok(ufwFilter))
			},
			wantCalls: []string{nftFilter, nftNat},
			want:      Backend{Binary: "iptables-nft", Reason: "forced to nf_tables by configuration"},
		},
		{
			name:       "forced legacy through plain iptables",
			preference: BackendLegacy,
			script: func(f *fakeRunner) {
				f.on(legacyFilter, notFound()).on(plainVersion, ok("iptables v1.6.1\n"))
			},
			wantCalls: []string{legacyFilter, plainVersion, plainFilter, plainNat},
			want:      Backend{Binary: "iptables", Reason: "forced to legacy by configuration"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			tt.script(f)
			g := guardWith(f, tt.preference)
			if _, ok := g.Backend(); ok {
				t.Fatal("Backend reported a backend before detection")
			}
			check := iptablesCheck(t, g)
			if !check.OK || check.Detail != "using "+tt.want.Binary+": "+tt.want.Reason {
				t.Errorf("iptables self-check = %+v, want ok with detail %q", check, "using "+tt.want.Binary+": "+tt.want.Reason)
			}
			if got, ok := g.Backend(); !ok || got != tt.want {
				t.Errorf("Backend() = %+v, %v; want %+v", got, ok, tt.want)
			}
			assertCalls(t, f.calls[:min(len(tt.wantCalls), len(f.calls))], tt.wantCalls)
		})
	}
}

func TestBackendUnavailable(t *testing.T) {
	tests := []struct {
		name         string
		preference   BackendPreference
		script       func(*fakeRunner)
		wantAttempts int
	}{
		{
			name: "auto, nothing works",
			script: func(f *fakeRunner) {
				f.on(nftFilter, fail(noPermission)).
					on(legacyFilter, fail(noPermission)).
					on(plainVersion, notFound())
			},
			wantAttempts: 3,
		},
		{
			name:       "forced nft on a legacy-only host",
			preference: BackendNft,
			script: func(f *fakeRunner) {
				f.on(nftFilter, notFound()).on(plainVersion, ok(legacyVersion))
			},
			wantAttempts: 1,
		},
		{
			name:       "forced legacy, plain iptables prints an unknown backend",
			preference: BackendLegacy,
			script: func(f *fakeRunner) {
				f.on(legacyFilter, notFound()).on(plainVersion, ok("iptables v9.9 (future)"))
			},
			wantAttempts: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			// Every detection runs the script once: two operations, then
			// the iptables and NET_ADMIN checks of the self-check.
			for range 4 {
				tt.script(f)
			}
			g := guardWith(f, tt.preference)
			for _, op := range []func() error{
				func() error { return g.InstallFirewall(context.Background(), testRules, uiPort) },
				func() error { return g.RemoveFirewall(context.Background()) },
			} {
				var noBackend *NoBackendError
				if err := op(); !errors.As(err, &noBackend) || len(noBackend.Attempts) != tt.wantAttempts {
					t.Fatalf("err = %v, want *NoBackendError with %d attempts", err, tt.wantAttempts)
				}
			}
			if _, ok := g.Backend(); ok {
				t.Error("a failed detection was cached")
			}
			if check := iptablesCheck(t, g); check.OK || !strings.Contains(check.Detail, "no usable iptables backend") {
				t.Errorf("iptables self-check = %+v, want a failure naming the attempts", check)
			}
		})
	}
}

func TestBackendIsDetectedOnce(t *testing.T) {
	f := newFakeRunner()
	f.on(legacyFilter, notFound())
	g := New(f)
	for range 2 {
		iptablesCheck(t, g)
	}
	detections := 0
	for _, call := range f.calls {
		switch {
		case strings.Contains(call, " -t filter -S") || call == plainVersion:
			detections++
		case call != ruleShow && !strings.HasPrefix(call, "iptables-nft -w "):
			t.Errorf("call %q: want the detected iptables-nft", call)
		}
	}
	if detections != 3 {
		t.Errorf("ran %d detection probes, want 3 of a single detection: %v", detections, f.calls)
	}
}

func TestParseVersionKind(t *testing.T) {
	tests := []struct {
		out     string
		want    xtablesKind
		wantErr bool
	}{
		{out: nftVersion, want: kindNft},
		{out: legacyVersion, want: kindLegacy},
		{out: "iptables v1.8.7 (legacy)\nextra line\n", want: kindLegacy},
		{out: "iptables v1.6.1\n", want: kindLegacy},
		{out: "iptables v9.9 (future)", wantErr: true},
		{out: "", wantErr: true},
		{out: "sh: iptables: not found", wantErr: true},
	}
	for _, tt := range tests {
		got, err := parseVersionKind(tt.out)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("parseVersionKind(%q) = %q, %v; want %q, error %v", tt.out, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestCountHostRules(t *testing.T) {
	tests := []struct {
		name    string
		listing string
		want    int
	}{
		{"empty output", "", 0},
		{"ACCEPT policies only", emptyFilter, 0},
		{"TunnelDeck's own chains and jumps", ownChainsOnly, 0},
		{"DROP policies and rules", ufwFilter, 4},
		{"warning comment and nat rules", dockerDNSNat, 2},
	}
	for _, tt := range tests {
		if got := countHostRules(tt.listing); got != tt.want {
			t.Errorf("%s: countHostRules = %d, want %d", tt.name, got, tt.want)
		}
	}
}

// guardWith returns a Guard with preference; empty means New's default.
func guardWith(f *fakeRunner, preference BackendPreference) *Guard {
	if preference == "" {
		return New(f)
	}
	return New(f, WithBackend(preference))
}

// iptablesCheck runs the self-check and returns its iptables result.
func iptablesCheck(t *testing.T, g *Guard) CheckResult {
	t.Helper()
	for _, r := range g.SelfCheck(context.Background()) {
		if r.ID == CheckIptables {
			return r
		}
	}
	t.Fatal("no iptables self-check result")
	return CheckResult{}
}
