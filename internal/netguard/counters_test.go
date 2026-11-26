package netguard

import (
	"context"
	"maps"
	"slices"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
)

// Listings of iptables -L <chain> -v -x -n as the two backends print them.
const (
	legacyInputListing = `Chain TUNNELDECK-INPUT (1 references)
    pkts      bytes target     prot opt in     out     source               destination
       3      180 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:8080 /* tdfixed:ui-port */
    1200   960000 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED /* tdfixed:established */
      17     1020 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22 /* tdrule:ssh */
       2      104 REJECT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:23 /* tdrule:telnet */ reject-with tcp-reset
       1       52 REJECT     udp  --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:23 /* tdrule:telnet */ reject-with icmp-port-unreachable
      40     2400 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0
`
	nftForwardListing = `Chain TUNNELDECK-FORWARD (3 references)
    pkts      bytes target     prot opt in     out     source               destination
       0        0 DROP       0    --  !tdvpn0 !tdvpn0  0.0.0.0/0            0.0.0.0/0            /* tdfixed:kill-switch */
     900   720000 ACCEPT     0    --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED /* tdfixed:established */
       5      300 ACCEPT     6    --  tdvpn0 *       0.0.0.0/0            192.168.2.30         tcp dpt:443 ctstate DNAT /* tdrule:web */
`
	nftPreroutingListing = `Chain TUNNELDECK-PREROUTING (1 references)
    pkts      bytes target     prot opt in     out     source               destination
       5      300 DNAT       6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:443 /* tdrule:web */ to:192.168.2.30
`
)

// commentMissing is how iptables-legacy fails a rule with the comment
// match when the kernel lacks xt_comment.
const commentMissing = "iptables v1.8.7 (legacy): Couldn't load match `comment':No such file or directory"

func TestRuleCounters(t *testing.T) {
	f := newFakeRunner()
	f.on(legacy+"-L TUNNELDECK-INPUT -v -x -n", ok(legacyInputListing)).
		on(legacy+"-L TUNNELDECK-FORWARD -v -x -n", ok(nftForwardListing)).
		on(natPrefix+"-L TUNNELDECK-PREROUTING -v -x -n", ok(nftPreroutingListing))
	counters, available, err := newLegacyGuard(f).RuleCounters(context.Background())
	if err != nil || !available {
		t.Fatalf("RuleCounters = %v, %v", available, err)
	}
	// Each rule counts once per connection: the port forward "web" from
	// its FORWARD accept only, not from its DNAT line as well.
	want := map[string]domain.RuleCounters{
		"ssh":    {Packets: 17, Bytes: 1020},
		"telnet": {Packets: 3, Bytes: 156},
		"web":    {Packets: 5, Bytes: 300},
	}
	if !maps.Equal(counters, want) {
		t.Errorf("counters = %v, want %v", counters, want)
	}
	assertCalls(t, f.calls, slices.Concat(detectInstall,
		prefixed(legacy, "-L TUNNELDECK-INPUT -v -x -n", "-L TUNNELDECK-FORWARD -v -x -n")))
}

func TestRuleCountersOfMissingChains(t *testing.T) {
	f := newFakeRunner()
	f.on(legacy+"-L TUNNELDECK-INPUT -v -x -n", fail(noChain)).
		on(legacy+"-L TUNNELDECK-FORWARD -v -x -n", fail(noChain))
	counters, available, err := newLegacyGuard(f).RuleCounters(context.Background())
	if err != nil || !available || len(counters) != 0 || counters == nil {
		t.Fatalf("RuleCounters = %v, %v, %v; want an empty map", counters, available, err)
	}
}

func TestRuleCountersWithoutTheCommentMatch(t *testing.T) {
	f := newFakeRunner()
	f.on(probeComment, fail(commentMissing))
	g := newLegacyGuard(f)
	for range 2 {
		counters, available, err := g.RuleCounters(context.Background())
		if err != nil || available || counters != nil {
			t.Fatalf("RuleCounters = %v, %v, %v; want unavailable", counters, available, err)
		}
	}
	// The probe runs once; nothing is listed.
	assertCalls(t, f.calls, detectInstall)
}

func TestRuleCountersFailures(t *testing.T) {
	tests := []struct {
		name    string
		failing string
		wantErr string
	}{
		{"listing a chain", legacy + "-L TUNNELDECK-INPUT -v -x -n", "read counters of TUNNELDECK-INPUT"},
		{"creating the probe chain", legacy + "-N TUNNELDECK-EXT-PROBE", "probe the iptables extensions"},
		{"deleting the probe chain", legacy + "-X TUNNELDECK-EXT-PROBE", "probe the iptables extensions"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRunner()
			f.on(tt.failing, fail(noPermission))
			_, available, err := newLegacyGuard(f).RuleCounters(context.Background())
			if available || err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("RuleCounters = %v, %v; want %q", available, err, tt.wantErr)
			}
		})
	}
}

func TestCommentProbeReusesALeftoverChain(t *testing.T) {
	f := newFakeRunner()
	f.on(legacy+"-N TUNNELDECK-EXT-PROBE", fail("iptables: Chain already exists."))
	if _, available, err := newLegacyGuard(f).RuleCounters(context.Background()); err != nil || !available {
		t.Fatalf("RuleCounters = %v, %v", available, err)
	}
}

func TestAddRuleCountersSkipsMalformedLines(t *testing.T) {
	counters := make(map[string]domain.RuleCounters)
	addRuleCounters(counters, "Chain X (1 references)\n"+
		"    pkts      bytes target\n"+
		"     12K       3M ACCEPT  all  --  *  *  0.0.0.0/0  0.0.0.0/0  /* tdrule:rounded */\n"+
		"       1       60 ACCEPT  all  --  *  *  0.0.0.0/0  0.0.0.0/0  /* tdrule: */\n"+
		"       1       60 ACCEPT  all  --  *  *  0.0.0.0/0  0.0.0.0/0  /* other */\n")
	if len(counters) != 0 {
		t.Errorf("counters = %v, want none", counters)
	}
}
