package netguard

import (
	"context"
	"io/fs"
	"maps"
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

func TestSelfCheckDetailCodes(t *testing.T) {
	tests := []struct {
		name   string
		root   fstest.MapFS
		script func(*fakeRunner)
		want   map[string]string
	}{
		{
			name:   "all pass",
			root:   withTun(charDevice),
			script: func(*fakeRunner) {},
			want: map[string]string{
				CheckTunDevice: detailTunPresent, CheckIptables: detailIptablesForced, CheckIPTool: detailIPToolWorks,
				CheckNetAdmin: detailNetAdminWorks, CheckIPForward: detailIPForwardOn, CheckLAN: detailLANSubnets,
				CheckCounters: detailCountersOn, CheckSYNFlood: detailSYNFloodFull, CheckPingLimit: detailPingHashlimit,
				CheckMSSClamp: detailMSSClampOn, CheckReject: detailRejectPresent, CheckReplyRouting: detailReplyRoutingMark,
			},
		},
		{
			name: "no tun device, no ip tool, no NET_ADMIN, forwarding unreadable",
			root: fstest.MapFS{},
			script: func(f *fakeRunner) {
				f.on(ruleShow, fail("exec: \"ip\": executable file not found in $PATH")).
					on(legacy+"-N TUNNELDECK-PROBE", fail(noPermission))
			},
			want: map[string]string{
				CheckTunDevice: detailTunMissing, CheckIPTool: detailIPToolFailed,
				CheckNetAdmin: detailNetAdminFailed, CheckIPForward: detailIPForwardUnreadable,
			},
		},
		{
			name:   "tun is not a device",
			root:   withTun(0),
			script: func(*fakeRunner) {},
			want:   map[string]string{CheckTunDevice: detailTunNotCharDevice},
		},
		{
			name: "no iptables backend",
			root: withTun(charDevice),
			script: func(f *fakeRunner) {
				f.on("iptables-legacy -w -t filter -S", fail(noPermission), fail(noPermission), fail(noPermission)).
					on("iptables -V", ok(nftVersion), ok(nftVersion), ok(nftVersion))
			},
			want: map[string]string{
				CheckIptables: detailIptablesUnavailable, CheckNetAdmin: detailNetAdminUnverified,
				CheckCounters: detailExtensionsUnknown, CheckReplyRouting: detailExtensionsUnknown,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			tt.script(f)
			g := newLegacyGuard(f)
			g.root = tt.root
			for _, r := range g.SelfCheck(context.Background()) {
				if want, checked := tt.want[r.ID]; checked && r.DetailCode != want {
					t.Errorf("%s: detail code = %q, want %q (%+v)", r.ID, r.DetailCode, want, r)
				}
				if r.DetailCode == "" || r.Detail == "" {
					t.Errorf("%s: detail code %q and detail %q must both be set", r.ID, r.DetailCode, r.Detail)
				}
			}
		})
	}
}

func TestSelfCheckDetailParams(t *testing.T) {
	tests := []struct {
		name      string
		ipForward string
		lan       fakeResult
		id        string
		wantCode  string
		wantParam map[string]string
	}{
		{name: "forwarding off", ipForward: "0\n", lan: ok(lanListing), id: CheckIPForward,
			wantCode: detailIPForwardOff, wantParam: map[string]string{"value": "0"}},
		{name: "LAN subnets", ipForward: "1\n", lan: ok(lanListing), id: CheckLAN,
			wantCode: detailLANSubnets, wantParam: map[string]string{"subnets": "192.168.2.0/24 (eth0)"}},
		{name: "no LAN", ipForward: "1\n", lan: ok("1: lo    inet 127.0.0.1/8 scope host lo\n"), id: CheckLAN,
			wantCode: detailLANNone, wantParam: map[string]string{}},
		{name: "LAN detection fails", ipForward: "1\n", lan: fail("Cannot open netlink socket"), id: CheckLAN,
			wantCode: detailLANFailed},
		{name: "backend choice", ipForward: "1\n", lan: ok(lanListing), id: CheckIptables,
			wantCode: detailIptablesForced, wantParam: map[string]string{"binary": "iptables-legacy", "backend": "legacy"}},
		{name: "tun device path", ipForward: "1\n", lan: ok(lanListing), id: CheckTunDevice,
			wantCode: detailTunPresent, wantParam: map[string]string{"path": "/dev/net/tun"}},
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
			r := resultOf(t, g.SelfCheck(context.Background()), tt.id)
			if r.DetailCode != tt.wantCode {
				t.Errorf("detail code = %q, want %q", r.DetailCode, tt.wantCode)
			}
			for key, want := range tt.wantParam {
				if r.Params[key] != want {
					t.Errorf("param %s = %q, want %q (params %v)", key, r.Params[key], want, r.Params)
				}
			}
			if tt.wantParam == nil && r.Params["error"] == "" {
				t.Errorf("params = %v, want the error", r.Params)
			}
		})
	}
}

func TestExtensionDetailCodes(t *testing.T) {
	all := capabilities{has: map[extension]bool{
		extComment: true, extHashlimit: true, extLimit: true, extTCPMSS: true, extReject: true, extConnmark: true,
	}}
	limitOnly := capabilities{has: map[extension]bool{extLimit: true}}
	none := capabilities{has: map[extension]bool{}}
	tests := []struct {
		name       string
		check      func(capabilities) CheckResult
		caps       capabilities
		wantCode   string
		wantModule string
	}{
		{"counters on", checkCounters, all, detailCountersOn, moduleComment},
		{"counters off", checkCounters, none, detailCountersOff, moduleComment},
		{"SYN flood full", checkSYNFlood, all, detailSYNFloodFull, moduleHashlimit},
		{"SYN flood global", checkSYNFlood, limitOnly, detailSYNFloodGlobal, moduleHashlimit},
		{"SYN flood none", checkSYNFlood, none, detailSYNFloodNone, moduleHashlimit},
		{"ping by hashlimit", checkPingLimit, all, detailPingHashlimit, moduleHashlimit},
		{"ping by limit", checkPingLimit, limitOnly, detailPingLimit, moduleHashlimit},
		{"ping none", checkPingLimit, none, detailPingNone, moduleHashlimit},
		{"MSS clamp on", checkMSSClamp, all, detailMSSClampOn, moduleTCPMSS},
		{"MSS clamp off", checkMSSClamp, none, detailMSSClampOff, moduleTCPMSS},
		{"REJECT present", checkReject, all, detailRejectPresent, moduleReject},
		{"REJECT missing", checkReject, none, detailRejectMissing, moduleReject},
		{"replies by connmark", checkReplyRouting, all, detailReplyRoutingMark, moduleConnmark},
		{"replies by address", checkReplyRouting, none, detailReplyRoutingAddress, moduleConnmark},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.check(tt.caps)
			if r.DetailCode != tt.wantCode || r.Params["module"] != tt.wantModule || r.Detail == "" {
				t.Errorf("result = %+v, want code %q with module %q and an English detail", r, tt.wantCode, tt.wantModule)
			}
		})
	}
}

func TestMixedBackendDetailParams(t *testing.T) {
	b := mixedBackend(probe{binary: "iptables-nft", kind: kindNft, rules: 2}, probe{binary: "iptables-legacy", kind: kindLegacy, rules: 4},
		backendChoice{nftRules: 2, legacyRules: 4})
	want := map[string]string{"binary": "iptables-legacy", "backend": "legacy", "nftRules": "2", "legacyRules": "4"}
	if got := b.choice.params(b.Binary); !maps.Equal(got, want) || b.choice.code != detailIptablesMixed || !b.Mixed {
		t.Errorf("mixed backend = %+v, params %v; want %v", b, got, want)
	}
}

// resultOf returns the result with id.
func resultOf(t *testing.T, results []CheckResult, id string) CheckResult {
	t.Helper()
	for _, r := range results {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no %s result", id)
	return CheckResult{}
}
