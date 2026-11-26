package netguard

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
)

const neighShow = "ip -4 neigh show"

// neighListing has an entry of every kind; only the first four on eth0 and
// the one outside the LAN subnet are usable.
const neighListing = "192.168.2.1 dev eth0 lladdr 3C:A6:2F:00:00:01 router REACHABLE\n" +
	"192.168.2.30 dev eth0 lladdr 3c:a6:2f:00:00:30 STALE\n" +
	"192.168.2.31 dev eth0 lladdr 3c:a6:2f:00:00:31 DELAY\n" +
	"192.168.2.32 dev eth0 lladdr 3c:a6:2f:00:00:32 PERMANENT\n" +
	"192.168.2.33 dev eth0 lladdr 3c:a6:2f:00:00:33 PROBE\n" +
	"192.168.2.40 dev eth0  FAILED\n" +
	"192.168.2.41 dev eth0  INCOMPLETE\n" +
	"192.168.2.30 dev eth0 lladdr 3c:a6:2f:00:00:99 STALE\n" +
	"192.168.7.5 dev eth0 lladdr 3c:a6:2f:00:07:05 STALE\n" +
	"172.17.0.2 dev docker0 lladdr 02:42:ac:11:00:02 REACHABLE\n" +
	"10.8.0.1 dev tdvpn0 lladdr 00:00:00:00:00:00 REACHABLE\n" +
	"fe80::1 dev eth0 lladdr 3c:a6:2f:00:00:01 router STALE\n" +
	"\n"

func TestLANNeighbours(t *testing.T) {
	f := newFakeRunner()
	f.on(neighShow, ok(neighListing))
	devices, err := newLegacyGuard(f).LANNeighbours(context.Background())
	if err != nil {
		t.Fatalf("LANNeighbours: %v", err)
	}
	device := func(addr, mac, state string, onLAN bool) domain.LANDevice {
		return domain.LANDevice{Address: netip.MustParseAddr(addr), MAC: mac, State: state, OnLAN: onLAN}
	}
	want := []domain.LANDevice{
		device("192.168.2.1", "3c:a6:2f:00:00:01", "REACHABLE", true),
		device("192.168.2.30", "3c:a6:2f:00:00:30", "STALE", true),
		device("192.168.2.31", "3c:a6:2f:00:00:31", "DELAY", true),
		device("192.168.2.32", "3c:a6:2f:00:00:32", "PERMANENT", true),
		device("192.168.2.33", "3c:a6:2f:00:00:33", "PROBE", true),
		device("192.168.7.5", "3c:a6:2f:00:07:05", "STALE", false),
	}
	if !slices.Equal(devices, want) {
		t.Errorf("devices =\n  %v\nwant\n  %v", devices, want)
	}
	assertCalls(t, f.calls, []string{addrShow, neighShow})
}

func TestLANNeighboursFailures(t *testing.T) {
	tests := []struct {
		name    string
		script  func(*fakeRunner)
		wantErr string
	}{
		{
			name:    "listing the neighbours",
			script:  func(f *fakeRunner) { f.on(neighShow, fail(notPermitted)) },
			wantErr: "list LAN neighbours",
		},
		{
			name:    "detecting the LAN",
			script:  func(f *fakeRunner) { f.on(addrShow, fail(notPermitted)) },
			wantErr: "detect LAN subnets",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			tt.script(f)
			_, err := newLegacyGuard(f).LANNeighbours(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
