package netguard

import (
	"context"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
)

const (
	legacy = "iptables-legacy -w "
	uiPort = 8080
)

var testRules = []domain.HostAccessRule{
	{ID: "ssh", Protocol: domain.TransportTCP, Port: 22, Enabled: true},
	{ID: "wg", Protocol: domain.TransportUDP, Port: 51820, SourceCIDR: "192.168.1.0/24", Enabled: true},
	{ID: "web", Protocol: domain.TransportTCP, Port: 80, Enabled: false},
}

// Listings of the state InstallFirewall(testRules) leaves behind, as
// iptables -S prints them.
const (
	installedInputChain = "-N TUNNELDECK-INPUT\n" +
		"-A TUNNELDECK-INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n" +
		"-A TUNNELDECK-INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n" +
		"-A TUNNELDECK-INPUT -s 192.168.1.0/24 -p udp -m udp --dport 51820 -j ACCEPT\n" +
		"-A TUNNELDECK-INPUT -j DROP\n"
	installedInput = "-P INPUT ACCEPT\n" +
		"-A INPUT -i tdvpn0 -j TUNNELDECK-INPUT\n" +
		"-A INPUT -i lo -j ACCEPT\n"
	installedForwardChain = "-N TUNNELDECK-FORWARD\n-A TUNNELDECK-FORWARD -j DROP\n"
	installedForward      = "-P FORWARD ACCEPT\n" +
		"-A FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD\n" +
		"-A FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD\n" +
		"-A FORWARD -j DOCKER-USER\n"
)

func scriptFresh(f *fakeRunner) {
	f.on(legacy+"-S TUNNELDECK-INPUT", fail(noChain)).
		on(legacy+"-S TUNNELDECK-FORWARD", fail(noChain)).
		on(legacy+"-S INPUT", ok("-P INPUT ACCEPT\n")).
		on(legacy+"-S FORWARD", ok("-P FORWARD ACCEPT\n")).
		on(legacy+"-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT", fail(noTarget)).
		on(legacy+"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD", fail(badRule)).
		on(legacy+"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD", fail(badRule))
}

func scriptInstalled(f *fakeRunner) {
	f.on(legacy+"-S TUNNELDECK-INPUT", ok(installedInputChain)).
		on(legacy+"-S INPUT", ok(installedInput)).
		on(legacy+"-S TUNNELDECK-FORWARD", ok(installedForwardChain)).
		on(legacy+"-S FORWARD", ok(installedForward))
}

var detectLegacy = []string{"iptables-legacy -w -L -n"}

var freshInputCalls = prefixed(legacy,
	"-S TUNNELDECK-INPUT",
	"-N TUNNELDECK-INPUT",
	"-A TUNNELDECK-INPUT -j DROP",
	"-S INPUT",
	"-I INPUT 1 -i tdvpn0 -j DROP",
	"-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT",
	"-I INPUT 1 -i tdvpn0 -j TUNNELDECK-INPUT",
	"-D INPUT -i tdvpn0 -j DROP",
	"-A TUNNELDECK-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
	"-A TUNNELDECK-INPUT -p tcp --dport 22 -j ACCEPT",
	"-A TUNNELDECK-INPUT -p udp --dport 51820 -s 192.168.1.0/24 -j ACCEPT",
	"-A TUNNELDECK-INPUT -j DROP",
	"-D TUNNELDECK-INPUT 1",
)

var freshForwardCalls = prefixed(legacy,
	"-S TUNNELDECK-FORWARD",
	"-N TUNNELDECK-FORWARD",
	"-A TUNNELDECK-FORWARD -j DROP",
	"-S FORWARD",
	"-I FORWARD 1 -i tdvpn0 -j DROP",
	"-I FORWARD 1 -o tdvpn0 -j DROP",
	"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD",
	"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD",
	"-I FORWARD 1 -o tdvpn0 -j TUNNELDECK-FORWARD",
	"-I FORWARD 1 -i tdvpn0 -j TUNNELDECK-FORWARD",
	"-D FORWARD -i tdvpn0 -j DROP",
	"-D FORWARD -o tdvpn0 -j DROP",
	"-A TUNNELDECK-FORWARD -j DROP",
	"-D TUNNELDECK-FORWARD 1",
)

var reinstallForwardCalls = prefixed(legacy,
	"-S TUNNELDECK-FORWARD",
	"-S FORWARD",
	"-A TUNNELDECK-FORWARD -j DROP",
	"-D TUNNELDECK-FORWARD 1",
)

func TestInstallFirewallSequences(t *testing.T) {
	tests := []struct {
		name   string
		script func(*fakeRunner)
		rules  []domain.HostAccessRule
		want   []string
	}{
		{
			name:   "fresh install",
			script: scriptFresh,
			rules:  testRules,
			want:   slices.Concat(detectLegacy, freshInputCalls, freshForwardCalls),
		},
		{
			name:   "rule change appends new content and trims the old",
			script: scriptInstalled,
			rules: []domain.HostAccessRule{
				{Protocol: domain.TransportTCP, Port: 443, SourceCIDR: "10.0.0.0/8", Enabled: true},
			},
			want: slices.Concat(detectLegacy, prefixed(legacy,
				"-S TUNNELDECK-INPUT",
				"-S INPUT",
				"-A TUNNELDECK-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
				"-A TUNNELDECK-INPUT -p tcp --dport 443 -s 10.0.0.0/8 -j ACCEPT",
				"-A TUNNELDECK-INPUT -j DROP",
				"-D TUNNELDECK-INPUT 1",
				"-D TUNNELDECK-INPUT 1",
				"-D TUNNELDECK-INPUT 1",
				"-D TUNNELDECK-INPUT 1",
			), reinstallForwardCalls),
		},
		{
			name: "existing chain without trailing DROP is sealed first",
			script: func(f *fakeRunner) {
				scriptInstalled(f)
				f.scripts[legacy+"-S TUNNELDECK-INPUT"] = []fakeResult{ok("-N TUNNELDECK-INPUT\n")}
			},
			rules: nil,
			want: slices.Concat(detectLegacy, prefixed(legacy,
				"-S TUNNELDECK-INPUT",
				"-A TUNNELDECK-INPUT -j DROP",
				"-S INPUT",
				"-A TUNNELDECK-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
				"-A TUNNELDECK-INPUT -j DROP",
				"-D TUNNELDECK-INPUT 1",
			), reinstallForwardCalls),
		},
		{
			name: "duplicate and displaced jumps are moved behind guards",
			script: func(f *fakeRunner) {
				scriptInstalled(f)
				f.scripts[legacy+"-S INPUT"] = []fakeResult{ok("-P INPUT ACCEPT\n" +
					"-A INPUT -i tdvpn0 -j TUNNELDECK-INPUT\n" +
					"-A INPUT -i tdvpn0 -j TUNNELDECK-INPUT\n")}
				f.scripts[legacy+"-S FORWARD"] = []fakeResult{ok("-P FORWARD DROP\n" +
					"-A FORWARD -j DOCKER-USER\n" +
					"-A FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD\n" +
					"-A FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD\n")}
				f.on(legacy+"-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT", ok(""), ok(""), fail(badRule)).
					on(legacy+"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD", ok(""), fail(badRule)).
					on(legacy+"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD", ok(""), fail(badRule))
			},
			rules: nil,
			want: slices.Concat(detectLegacy, prefixed(legacy,
				"-S TUNNELDECK-INPUT",
				"-S INPUT",
				"-I INPUT 1 -i tdvpn0 -j DROP",
				"-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT",
				"-D INPUT -i tdvpn0 -j TUNNELDECK-INPUT",
				"-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT",
				"-D INPUT -i tdvpn0 -j TUNNELDECK-INPUT",
				"-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT",
				"-I INPUT 1 -i tdvpn0 -j TUNNELDECK-INPUT",
				"-D INPUT -i tdvpn0 -j DROP",
				"-A TUNNELDECK-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
				"-A TUNNELDECK-INPUT -j DROP",
				"-D TUNNELDECK-INPUT 1",
				"-D TUNNELDECK-INPUT 1",
				"-D TUNNELDECK-INPUT 1",
				"-D TUNNELDECK-INPUT 1",
				"-S TUNNELDECK-FORWARD",
				"-S FORWARD",
				"-I FORWARD 1 -i tdvpn0 -j DROP",
				"-I FORWARD 1 -o tdvpn0 -j DROP",
				"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD",
				"-D FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD",
				"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD",
				"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD",
				"-D FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD",
				"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD",
				"-I FORWARD 1 -o tdvpn0 -j TUNNELDECK-FORWARD",
				"-I FORWARD 1 -i tdvpn0 -j TUNNELDECK-FORWARD",
				"-D FORWARD -i tdvpn0 -j DROP",
				"-D FORWARD -o tdvpn0 -j DROP",
				"-A TUNNELDECK-FORWARD -j DROP",
				"-D TUNNELDECK-FORWARD 1",
			)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			tt.script(f)
			if err := New(f).InstallFirewall(context.Background(), tt.rules, uiPort); err != nil {
				t.Fatalf("InstallFirewall: %v", err)
			}
			assertCalls(t, f.calls, tt.want)
		})
	}
}

func TestInstallFirewallIsIdempotent(t *testing.T) {
	f := newFakeRunner()
	scriptFresh(f)
	g := New(f)
	if err := g.InstallFirewall(context.Background(), testRules, uiPort); err != nil {
		t.Fatalf("first install: %v", err)
	}
	f.takeCalls()

	want := slices.Concat(prefixed(legacy,
		"-S TUNNELDECK-INPUT",
		"-S INPUT",
		"-A TUNNELDECK-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-A TUNNELDECK-INPUT -p tcp --dport 22 -j ACCEPT",
		"-A TUNNELDECK-INPUT -p udp --dport 51820 -s 192.168.1.0/24 -j ACCEPT",
		"-A TUNNELDECK-INPUT -j DROP",
		"-D TUNNELDECK-INPUT 1",
		"-D TUNNELDECK-INPUT 1",
		"-D TUNNELDECK-INPUT 1",
		"-D TUNNELDECK-INPUT 1",
	), reinstallForwardCalls)
	for run := range 2 {
		scriptInstalled(f)
		if err := g.InstallFirewall(context.Background(), testRules, uiPort); err != nil {
			t.Fatalf("re-install %d: %v", run, err)
		}
		calls := f.takeCalls()
		assertCalls(t, calls, want)
		for _, call := range calls {
			if strings.Contains(call, " -I ") || strings.Contains(call, " -N ") {
				t.Errorf("re-install %d ran %q; jumps and chains must not be added again", run, call)
			}
		}
	}
}

func TestInstallFirewallRejectsInvalidRulesBeforeAnyCommand(t *testing.T) {
	tests := []struct {
		name  string
		rules []domain.HostAccessRule
		field string
	}{
		{
			name:  "enabled rule on the UI port",
			rules: []domain.HostAccessRule{{Protocol: domain.TransportTCP, Port: uiPort, Enabled: true}},
			field: "rules[0].port",
		},
		{
			name: "disabled rule on the UI port",
			rules: []domain.HostAccessRule{
				{Protocol: domain.TransportTCP, Port: 22, Enabled: true},
				{Protocol: domain.TransportUDP, Port: uiPort},
			},
			field: "rules[1].port",
		},
		{
			name:  "invalid protocol",
			rules: []domain.HostAccessRule{{Protocol: "icmp", Port: 1, Enabled: true}},
			field: "rules[0].protocol",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			err := New(f).InstallFirewall(context.Background(), tt.rules, uiPort)
			var v *domain.ValidationError
			if !errors.As(err, &v) || !errors.Is(err, domain.ErrValidation) {
				t.Fatalf("err = %v, want *domain.ValidationError", err)
			}
			if _, found := v.Fields[tt.field]; !found {
				t.Errorf("fields = %v, want %q", v.Fields, tt.field)
			}
			if len(f.calls) != 0 {
				t.Errorf("commands ran before validation: %v", f.calls)
			}
		})
	}
}

func TestBackendFallsBackToNftIptables(t *testing.T) {
	f := newFakeRunner()
	notFound := &CommandError{Name: "iptables-legacy", ExitCode: -1, Err: exec.ErrNotFound}
	f.on("iptables-legacy -w -L -n", fakeResult{err: notFound}).
		on("iptables -w -S TUNNELDECK-INPUT", ok(installedInputChain), ok(installedInputChain)).
		on("iptables -w -S INPUT", ok(installedInput), ok(installedInput)).
		on("iptables -w -S TUNNELDECK-FORWARD", ok(installedForwardChain), ok(installedForwardChain)).
		on("iptables -w -S FORWARD", ok(installedForward), ok(installedForward))
	g := New(f)
	for range 2 {
		if err := g.InstallFirewall(context.Background(), nil, uiPort); err != nil {
			t.Fatalf("InstallFirewall: %v", err)
		}
	}
	assertCalls(t, f.calls[:3], []string{"iptables-legacy -w -L -n", "iptables -w -L -n", "iptables -w -S TUNNELDECK-INPUT"})
	for _, call := range f.calls[2:] {
		if !strings.HasPrefix(call, "iptables -w ") || strings.Contains(call, "-L -n") {
			t.Errorf("call %q: want the detected backend without new detection", call)
		}
	}
}

func TestBackendUnavailable(t *testing.T) {
	f := newFakeRunner()
	f.on("iptables-legacy -w -L -n", fail(noPermission), fail(noPermission)).
		on("iptables -w -L -n", fail(noPermission), fail(noPermission))
	g := New(f)
	for _, op := range []func() error{
		func() error { return g.InstallFirewall(context.Background(), testRules, uiPort) },
		func() error { return g.RemoveFirewall(context.Background()) },
	} {
		err := op()
		var noBackend *NoBackendError
		if !errors.As(err, &noBackend) || len(noBackend.Attempts) != 2 {
			t.Fatalf("err = %v, want *NoBackendError with two attempts", err)
		}
		if !strings.Contains(err.Error(), "Permission denied") {
			t.Errorf("err = %q, want the stderr of the attempts", err)
		}
	}
	assertCalls(t, f.calls, []string{
		"iptables-legacy -w -L -n", "iptables -w -L -n",
		"iptables-legacy -w -L -n", "iptables -w -L -n",
	})
}

func TestConntrackFallsBackToStateMatch(t *testing.T) {
	const conntrackRule = legacy + "-A TUNNELDECK-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
	const stateRule = legacy + "-A TUNNELDECK-INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"
	f := newFakeRunner()
	scriptInstalled(f)
	f.on(conntrackRule, fail("iptables v1.8.7 (legacy): Couldn't load match `conntrack':No such file or directory"))
	g := New(f)
	if err := g.InstallFirewall(context.Background(), nil, uiPort); err != nil {
		t.Fatalf("first install: %v", err)
	}
	calls := f.takeCalls()
	assertCalls(t, calls[3:6], []string{conntrackRule, stateRule, legacy + "-A TUNNELDECK-INPUT -j DROP"})

	scriptInstalled(f)
	if err := g.InstallFirewall(context.Background(), nil, uiPort); err != nil {
		t.Fatalf("second install: %v", err)
	}
	calls = f.takeCalls()
	if slices.Contains(calls, conntrackRule) || !slices.Contains(calls, stateRule) {
		t.Errorf("second install must use the detected state match directly: %v", calls)
	}
}

func TestConntrackAndStateBothFail(t *testing.T) {
	f := newFakeRunner()
	scriptInstalled(f)
	f.on(legacy+"-A TUNNELDECK-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", fail("no conntrack")).
		on(legacy+"-A TUNNELDECK-INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT", fail("no state"))
	err := New(f).InstallFirewall(context.Background(), nil, uiPort)
	if err == nil || !strings.Contains(err.Error(), "no conntrack") || !strings.Contains(err.Error(), "no state") {
		t.Fatalf("err = %v, want both match failures", err)
	}
	if slices.Contains(f.calls, legacy+"-D TUNNELDECK-INPUT 1") {
		t.Error("old content was trimmed although the new content is incomplete")
	}
}

func TestInstallFirewallFailureLeavesDropInPlace(t *testing.T) {
	const failing = legacy + "-A TUNNELDECK-INPUT -p tcp --dport 22 -j ACCEPT"
	f := newFakeRunner()
	scriptFresh(f)
	f.on(failing, fail("iptables: Resource temporarily unavailable."))

	err := New(f).InstallFirewall(context.Background(), testRules, uiPort)
	if err == nil {
		t.Fatal("InstallFirewall succeeded despite a failing command")
	}
	for _, part := range []string{"TUNNELDECK-INPUT", "--dport 22", "Resource temporarily unavailable"} {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("err = %q, want it to contain %q", err, part)
		}
	}
	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) {
		t.Errorf("err = %v, want it to wrap *CommandError", err)
	}
	failedAt := slices.Index(f.calls, failing)
	sealedAt := slices.Index(f.calls, legacy+"-A TUNNELDECK-INPUT -j DROP")
	jumpAt := slices.Index(f.calls, legacy+"-I INPUT 1 -i tdvpn0 -j TUNNELDECK-INPUT")
	if sealedAt < 0 || jumpAt < sealedAt || failedAt < jumpAt {
		t.Errorf("chain must end with DROP before its jump exists: %v", f.calls)
	}
	if slices.Contains(f.calls, legacy+"-D TUNNELDECK-INPUT 1") {
		t.Error("the sealing DROP was deleted after a failure")
	}
	assertCalls(t, f.calls[len(f.calls)-len(freshForwardCalls):], freshForwardCalls)
}

func TestInstallFirewallEarlyFailures(t *testing.T) {
	tests := []struct {
		name      string
		failing   string
		stderr    string
		forbidden string
	}{
		{"listing the chain", legacy + "-S TUNNELDECK-INPUT", noPermission, legacy + "-S INPUT"},
		{"creating the chain", legacy + "-N TUNNELDECK-INPUT", "iptables: Chain already exists.", legacy + "-I INPUT 1 -i tdvpn0 -j DROP"},
		{"sealing the chain", legacy + "-A TUNNELDECK-INPUT -j DROP", "iptables: Index of insertion too big.", legacy + "-S INPUT"},
		{"listing the parent", legacy + "-S INPUT", noPermission, legacy + "-I INPUT 1 -i tdvpn0 -j DROP"},
		{"inserting the guard", legacy + "-I INPUT 1 -i tdvpn0 -j DROP", noPermission, legacy + "-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT"},
		{"checking a jump", legacy + "-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT", noPermission, legacy + "-D INPUT -i tdvpn0 -j DROP"},
		{"inserting the jump", legacy + "-I INPUT 1 -i tdvpn0 -j TUNNELDECK-INPUT", noPermission, legacy + "-D INPUT -i tdvpn0 -j DROP"},
		{"removing the guard", legacy + "-D INPUT -i tdvpn0 -j DROP", noPermission, legacy + "-D TUNNELDECK-INPUT 1"},
		{"trimming old content", legacy + "-D TUNNELDECK-INPUT 1", noPermission, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			scriptFresh(f)
			f.scripts[tt.failing] = []fakeResult{fail(tt.stderr)}
			err := New(f).InstallFirewall(context.Background(), testRules, uiPort)
			if err == nil || !strings.Contains(err.Error(), tt.stderr) {
				t.Fatalf("err = %v, want the stderr %q", err, tt.stderr)
			}
			if tt.forbidden != "" && slices.Contains(f.calls, tt.forbidden) {
				t.Errorf("%q ran after the failure", tt.forbidden)
			}
		})
	}
}

func TestRemoveFirewall(t *testing.T) {
	removeJumps := func(f *fakeRunner) {
		for _, cmd := range []string{
			"-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT",
			"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD",
			"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD",
		} {
			f.on(legacy+cmd, ok(""), fail(badRule))
		}
	}
	tests := []struct {
		name   string
		script func(*fakeRunner)
		want   []string
	}{
		{
			name:   "installed state",
			script: removeJumps,
			want: slices.Concat(detectLegacy, prefixed(legacy,
				"-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT",
				"-D INPUT -i tdvpn0 -j TUNNELDECK-INPUT",
				"-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT",
				"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD",
				"-D FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD",
				"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD",
				"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD",
				"-D FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD",
				"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD",
				"-F TUNNELDECK-INPUT",
				"-X TUNNELDECK-INPUT",
				"-F TUNNELDECK-FORWARD",
				"-X TUNNELDECK-FORWARD",
			)),
		},
		{
			name: "already absent",
			script: func(f *fakeRunner) {
				f.on(legacy+"-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT", fail(noTarget)).
					on(legacy+"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD", fail(noTarget)).
					on(legacy+"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD", fail(noTarget)).
					on(legacy+"-F TUNNELDECK-INPUT", fail(noChain)).
					on(legacy+"-F TUNNELDECK-FORWARD", fail(noChain))
			},
			want: slices.Concat(detectLegacy, prefixed(legacy,
				"-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT",
				"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD",
				"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD",
				"-F TUNNELDECK-INPUT",
				"-F TUNNELDECK-FORWARD",
			)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			tt.script(f)
			if err := New(f).RemoveFirewall(context.Background()); err != nil {
				t.Fatalf("RemoveFirewall: %v", err)
			}
			assertCalls(t, f.calls, tt.want)
		})
	}
}

func TestRemoveFirewallFailures(t *testing.T) {
	tests := []struct {
		name    string
		script  func(*fakeRunner)
		wantErr string
	}{
		{
			name: "permission denied is not mistaken for absence",
			script: func(f *fakeRunner) {
				f.on(legacy+"-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT", fail(noPermission))
			},
			wantErr: "Permission denied",
		},
		{
			name: "deleting a jump fails",
			script: func(f *fakeRunner) {
				f.on(legacy+"-D INPUT -i tdvpn0 -j TUNNELDECK-INPUT", fail(noPermission))
			},
			wantErr: "-D INPUT",
		},
		{
			name:    "a rule that never disappears",
			script:  func(*fakeRunner) {},
			wantErr: "after 64 deletions",
		},
		{
			name: "deleting a chain fails",
			script: func(f *fakeRunner) {
				for _, cmd := range []string{
					"-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT",
					"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD",
					"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD",
				} {
					f.on(legacy+cmd, fail(badRule))
				}
				f.on(legacy+"-X TUNNELDECK-INPUT", fail("iptables: Too many links."))
			},
			wantErr: "Too many links",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			tt.script(f)
			err := New(f).RemoveFirewall(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}
