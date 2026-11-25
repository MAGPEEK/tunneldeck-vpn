package netguard

import (
	"context"
	"net/netip"
	"slices"
	"testing"
)

func TestParseLANAddresses(t *testing.T) {
	listing := lanListing +
		"4: br-3f2a9c1d7e6b    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-3f2a9c1d7e6b\\ ...\n" +
		"5: veth1a2b3c@if4    inet 169.254.1.1/16 scope link veth1a2b3c\\ ...\n" +
		"6: ovs_eth1    inet 10.10.4.20/16 brd 10.10.255.255 scope global ovs_eth1\\ ...\n" +
		"8: eth0    inet 192.168.2.11/24 brd 192.168.2.255 scope global secondary eth0\\ ...\n" +
		"9: eth2@if12    inet 172.30.0.5/24 brd 172.30.0.255 scope global eth2\\ ...\n" +
		"10: wg0    inet 10.99.0.1/24 scope global wg0\\ ...\n" +
		"11: tun3    inet 10.98.0.1/24 scope global tun3\\ ...\n" +
		"12: eth3    inet6 fd00::1/64 scope global\n" +
		"13: eth4    inet bogus scope global eth4\n" +
		"garbage\n"
	addrs := parseLANAddresses(listing)
	want := []string{"192.168.2.0/24", "10.10.0.0/16", "172.30.0.0/24"}
	var got []string
	for _, p := range subnets(addrs) {
		got = append(got, p.String())
	}
	if !slices.Equal(got, want) {
		t.Fatalf("subnets = %v, want %v", got, want)
	}
	if addrs[0].iface != "eth0" || addrs[0].prefix != netip.MustParsePrefix("192.168.2.10/24") || addrs[3].iface != "eth2" {
		t.Errorf("addresses = %+v", addrs)
	}
	if got := describeLAN(addrs[:2]); got != "192.168.2.0/24 (eth0), 10.10.0.0/16 (ovs_eth1)" {
		t.Errorf("describeLAN = %q", got)
	}
}

func TestLANSubnets(t *testing.T) {
	f := newFakeRunner()
	g := newLegacyGuard(f)
	got, err := g.LANSubnets(context.Background())
	if err != nil || !slices.Equal(got, []netip.Prefix{netip.MustParsePrefix("192.168.2.0/24")}) {
		t.Fatalf("LANSubnets = %v, %v", got, err)
	}
	f.on(addrShow, fail("exec: \"ip\": executable file not found in $PATH"))
	if _, err := g.LANSubnets(context.Background()); err == nil {
		t.Fatal("LANSubnets succeeded despite a failing ip")
	}
}
