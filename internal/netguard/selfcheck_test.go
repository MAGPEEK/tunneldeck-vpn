package netguard

import (
	"context"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

func withTun(mode fs.FileMode) fstest.MapFS {
	return fstest.MapFS{
		"dev/net/tun":                  &fstest.MapFile{Mode: mode},
		"proc/sys/net/ipv4/ip_forward": &fstest.MapFile{Data: []byte("1\n")},
	}
}

const charDevice = fs.ModeDevice | fs.ModeCharDevice

func TestSelfCheck(t *testing.T) {
	tests := []struct {
		name      string
		root      fstest.MapFS
		script    func(*fakeRunner)
		wantOK    map[string]bool
		wantCalls []string
		// counterCalls follow the LAN detection; nil means a passing probe.
		counterCalls []string
	}{
		{
			name:   "all pass",
			root:   withTun(charDevice),
			script: func(*fakeRunner) {},
			wantOK: map[string]bool{CheckTunDevice: true, CheckIptables: true, CheckIPTool: true, CheckNetAdmin: true, CheckIPForward: true, CheckLAN: true, CheckCounters: true, CheckSYNFlood: true, CheckPingLimit: true, CheckMSSClamp: true, CheckReject: true, CheckReplyRouting: true},
			wantCalls: slices.Concat(detectLegacy, []string{
				ruleShow,
				legacy + "-N TUNNELDECK-PROBE",
				legacy + "-X TUNNELDECK-PROBE",
			}),
		},
		{
			name:   "leftover probe chain is only deleted",
			root:   withTun(charDevice),
			script: func(f *fakeRunner) { f.on(legacy+"-N TUNNELDECK-PROBE", fail("iptables: Chain already exists.")) },
			wantOK: map[string]bool{CheckTunDevice: true, CheckIptables: true, CheckIPTool: true, CheckNetAdmin: true, CheckIPForward: true, CheckLAN: true, CheckCounters: true, CheckSYNFlood: true, CheckPingLimit: true, CheckMSSClamp: true, CheckReject: true, CheckReplyRouting: true},
			wantCalls: slices.Concat(detectLegacy, []string{
				ruleShow,
				legacy + "-N TUNNELDECK-PROBE",
				legacy + "-X TUNNELDECK-PROBE",
			}),
		},
		{
			name: "no tun device, no ip tool, no NET_ADMIN for chains",
			root: fstest.MapFS{},
			script: func(f *fakeRunner) {
				f.on(ruleShow, fail("exec: \"ip\": executable file not found in $PATH")).
					on(legacy+"-N TUNNELDECK-PROBE", fail(noPermission))
			},
			wantOK: map[string]bool{CheckTunDevice: false, CheckIptables: true, CheckIPTool: false, CheckNetAdmin: false, CheckIPForward: false, CheckLAN: true, CheckCounters: true, CheckSYNFlood: true, CheckPingLimit: true, CheckMSSClamp: true, CheckReject: true, CheckReplyRouting: true},
			wantCalls: slices.Concat(detectLegacy, []string{
				ruleShow,
				legacy + "-N TUNNELDECK-PROBE",
			}),
		},
		{
			name: "tun is not a device and probe deletion fails",
			root: withTun(0),
			script: func(f *fakeRunner) {
				f.on(legacy+"-X TUNNELDECK-PROBE", fail(noPermission))
			},
			wantOK: map[string]bool{CheckTunDevice: false, CheckIptables: true, CheckIPTool: true, CheckNetAdmin: false, CheckIPForward: true, CheckLAN: true, CheckCounters: true, CheckSYNFlood: true, CheckPingLimit: true, CheckMSSClamp: true, CheckReject: true, CheckReplyRouting: true},
			wantCalls: slices.Concat(detectLegacy, []string{
				ruleShow,
				legacy + "-N TUNNELDECK-PROBE",
				legacy + "-X TUNNELDECK-PROBE",
			}),
		},
		{
			name: "no iptables backend",
			root: withTun(charDevice),
			script: func(f *fakeRunner) {
				f.on("iptables-legacy -w -t filter -S", fail(noPermission), fail(noPermission), fail(noPermission)).
					on("iptables -V", ok(nftVersion), ok(nftVersion), ok(nftVersion))
			},
			wantOK: map[string]bool{CheckTunDevice: true, CheckIptables: false, CheckIPTool: true, CheckNetAdmin: false, CheckIPForward: true, CheckLAN: true, CheckCounters: false, CheckSYNFlood: false, CheckPingLimit: false, CheckMSSClamp: false, CheckReject: false, CheckReplyRouting: false},
			wantCalls: []string{
				"iptables-legacy -w -t filter -S", "iptables -V",
				ruleShow,
				"iptables-legacy -w -t filter -S", "iptables -V",
			},
			counterCalls: []string{"iptables-legacy -w -t filter -S", "iptables -V"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			tt.script(f)
			g := newLegacyGuard(f)
			g.root = tt.root
			results := g.SelfCheck(context.Background())
			if len(results) != len(tt.wantOK) {
				t.Fatalf("got %d results, want %d", len(results), len(tt.wantOK))
			}
			for _, r := range results {
				if r.OK != tt.wantOK[r.ID] {
					t.Errorf("%s: ok = %v, want %v (detail %q)", r.ID, r.OK, tt.wantOK[r.ID], r.Detail)
				}
				if r.Detail == "" {
					t.Errorf("%s: empty detail", r.ID)
				}
				if r.OK != (r.Hint == "") {
					t.Errorf("%s: hint %q must be set exactly when the check fails", r.ID, r.Hint)
				}
				if r.Warning != (slices.Contains(extensionChecks, r.ID) && !r.OK) {
					t.Errorf("%s: warning = %v; only a failed extension check is a warning", r.ID, r.Warning)
				}
			}
			counterCalls := tt.counterCalls
			if counterCalls == nil {
				counterCalls = probeCalls
			}
			assertCalls(t, f.calls, slices.Concat(tt.wantCalls, []string{addrShow}, counterCalls))
		})
	}
}

func TestSelfCheckForwardingAndLAN(t *testing.T) {
	tests := []struct {
		name      string
		ipForward string
		lan       fakeResult
		wantIDs   map[string]bool
		wantText  map[string]string
	}{
		{
			name: "forwarding on, LAN found", ipForward: "1\n", lan: ok(lanListing),
			wantIDs:  map[string]bool{CheckIPForward: true, CheckLAN: true, CheckCounters: true, CheckSYNFlood: true, CheckPingLimit: true, CheckMSSClamp: true, CheckReject: true, CheckReplyRouting: true},
			wantText: map[string]string{CheckLAN: "192.168.2.0/24 (eth0)"},
		},
		{
			name: "forwarding off, only loopback and Docker", ipForward: "0\n",
			lan:      ok("1: lo    inet 127.0.0.1/8 scope host lo\n3: docker0    inet 172.17.0.1/16 scope global docker0\n"),
			wantIDs:  map[string]bool{CheckIPForward: false, CheckLAN: false},
			wantText: map[string]string{CheckIPForward: "ip_forward = 0", CheckLAN: "no IPv4 address"},
		},
		{
			name: "ip fails", ipForward: "1", lan: fail("Cannot open netlink socket: Operation not permitted"),
			wantIDs:  map[string]bool{CheckIPForward: true, CheckLAN: false},
			wantText: map[string]string{CheckLAN: "detect LAN subnets"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			g := newLegacyGuard(f)
			f.always(addrShow, tt.lan)
			g.root = fstest.MapFS{
				"dev/net/tun":                  &fstest.MapFile{Mode: charDevice},
				"proc/sys/net/ipv4/ip_forward": &fstest.MapFile{Data: []byte(tt.ipForward)},
			}
			for _, r := range g.SelfCheck(context.Background()) {
				want, checked := tt.wantIDs[r.ID]
				if !checked {
					continue
				}
				if r.OK != want || !strings.Contains(r.Detail, tt.wantText[r.ID]) {
					t.Errorf("%s = %+v, want ok %v and detail with %q", r.ID, r, want, tt.wantText[r.ID])
				}
			}
		})
	}
}

func TestSelfCheckWithoutTheCommentMatch(t *testing.T) {
	f := newFakeRunner()
	f.on(probeComment, fail(commentMissing))
	g := newLegacyGuard(f)
	g.root = withTun(charDevice)
	for _, r := range g.SelfCheck(context.Background()) {
		switch {
		case r.ID == CheckCounters:
			if r.OK || !r.Warning || r.Hint != hintCounters || !strings.Contains(r.Detail, "comment match") {
				t.Errorf("counter check = %+v, want a warning with the hint", r)
			}
		case !r.OK:
			t.Errorf("%s failed: %+v", r.ID, r)
		}
	}
}
