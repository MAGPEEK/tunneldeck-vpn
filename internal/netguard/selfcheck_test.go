package netguard

import (
	"context"
	"io/fs"
	"testing"
	"testing/fstest"
)

func withTun(mode fs.FileMode) fstest.MapFS {
	return fstest.MapFS{"dev/net/tun": &fstest.MapFile{Mode: mode}}
}

const charDevice = fs.ModeDevice | fs.ModeCharDevice

func TestSelfCheck(t *testing.T) {
	tests := []struct {
		name      string
		root      fstest.MapFS
		script    func(*fakeRunner)
		wantOK    map[string]bool
		wantCalls []string
	}{
		{
			name:   "all pass",
			root:   withTun(charDevice),
			script: func(*fakeRunner) {},
			wantOK: map[string]bool{CheckTunDevice: true, CheckIptables: true, CheckIPTool: true, CheckNetAdmin: true},
			wantCalls: []string{
				"iptables-legacy -w -L -n",
				ruleShow,
				legacy + "-N TUNNELDECK-PROBE",
				legacy + "-X TUNNELDECK-PROBE",
			},
		},
		{
			name:   "leftover probe chain is only deleted",
			root:   withTun(charDevice),
			script: func(f *fakeRunner) { f.on(legacy+"-N TUNNELDECK-PROBE", fail("iptables: Chain already exists.")) },
			wantOK: map[string]bool{CheckTunDevice: true, CheckIptables: true, CheckIPTool: true, CheckNetAdmin: true},
			wantCalls: []string{
				"iptables-legacy -w -L -n",
				ruleShow,
				legacy + "-N TUNNELDECK-PROBE",
				legacy + "-X TUNNELDECK-PROBE",
			},
		},
		{
			name: "no tun device, no ip tool, no NET_ADMIN for chains",
			root: fstest.MapFS{},
			script: func(f *fakeRunner) {
				f.on(ruleShow, fail("exec: \"ip\": executable file not found in $PATH")).
					on(legacy+"-N TUNNELDECK-PROBE", fail(noPermission))
			},
			wantOK: map[string]bool{CheckTunDevice: false, CheckIptables: true, CheckIPTool: false, CheckNetAdmin: false},
			wantCalls: []string{
				"iptables-legacy -w -L -n",
				ruleShow,
				legacy + "-N TUNNELDECK-PROBE",
			},
		},
		{
			name: "tun is not a device and probe deletion fails",
			root: withTun(0),
			script: func(f *fakeRunner) {
				f.on(legacy+"-X TUNNELDECK-PROBE", fail(noPermission))
			},
			wantOK: map[string]bool{CheckTunDevice: false, CheckIptables: true, CheckIPTool: true, CheckNetAdmin: false},
			wantCalls: []string{
				"iptables-legacy -w -L -n",
				ruleShow,
				legacy + "-N TUNNELDECK-PROBE",
				legacy + "-X TUNNELDECK-PROBE",
			},
		},
		{
			name: "no iptables backend",
			root: withTun(charDevice),
			script: func(f *fakeRunner) {
				f.on("iptables-legacy -w -L -n", fail(noPermission), fail(noPermission)).
					on("iptables -w -L -n", fail(noPermission), fail(noPermission))
			},
			wantOK: map[string]bool{CheckTunDevice: true, CheckIptables: false, CheckIPTool: true, CheckNetAdmin: false},
			wantCalls: []string{
				"iptables-legacy -w -L -n", "iptables -w -L -n",
				ruleShow,
				"iptables-legacy -w -L -n", "iptables -w -L -n",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			tt.script(f)
			g := New(f)
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
			}
			assertCalls(t, f.calls, tt.wantCalls)
		})
	}
}
