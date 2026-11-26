//go:build integration && linux

// Integration test of the hit counters against real iptables, with tdvpn0
// as a TUN device so the test can inject packets that arrive from the
// tunnel. Run it like netguard_integration_test.go, with the TUN device
// passed in:
//
//	docker run --rm --cap-add NET_ADMIN --device /dev/net/tun -v "$PWD":/src -w /src golang:1.27 \
//	  sh -c 'apt-get update -qq && apt-get install -y -qq iptables iproute2 >/dev/null && go test -tags integration -run Integration -v ./internal/netguard/'

package netguard

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"unsafe"

	"tunneldeck/internal/domain"
)

// Addresses on the TUN device: the host's end and the sender of the
// injected packets.
var (
	tunHost   = netip.MustParseAddr("10.99.0.2")
	tunSender = netip.MustParseAddr("10.99.0.1")
)

func TestIntegrationCountersSurviveUnchangedReinstall(t *testing.T) {
	for _, backend := range []BackendPreference{BackendLegacy, BackendNft} {
		t.Run(string(backend), func(t *testing.T) {
			testCountersSurviveUnchangedReinstall(t, backend)
		})
	}
}

func testCountersSurviveUnchangedReinstall(t *testing.T, backend BackendPreference) {
	ctx := context.Background()
	runner := ExecRunner{}
	tun := openTUN(t)
	mustRun(t, runner, "ip", "addr", "add", tunHost.String()+"/24", "dev", DeviceName)
	mustRun(t, runner, "ip", "link", "set", DeviceName, "up")
	g := New(runner, WithBackend(backend))
	t.Cleanup(func() { _ = g.RemoveFirewall(ctx) })
	lan, err := g.LANSubnets(ctx)
	if err != nil || len(lan) == 0 {
		t.Fatalf("LANSubnets = %v, %v; want the container's network", lan, err)
	}

	udp := domain.LegacyHostRule(domain.FirewallRule{ID: "udp", Name: "UDP 5000", Direction: domain.DirectionInbound, Protocol: domain.ProtocolUDP,
		DestinationPort: domain.SinglePort(5000), Enabled: true})
	firewall := domain.Firewall{FirewallSettings: domain.DefaultFirewallSettings(), Rules: []domain.FirewallRule{udp}}
	install(t, g, firewall)
	sendUDP(t, tun, 5000, 3)
	assertPackets(t, g, "udp", 3)

	install(t, g, firewall)
	assertPackets(t, g, "udp", 3)
	sendUDP(t, tun, 5000, 2)
	assertPackets(t, g, "udp", 5)

	// A new outbound rule changes TUNNELDECK-FORWARD and -POSTROUTING
	// only; TUNNELDECK-INPUT keeps its counters.
	withOutbound := firewall
	withOutbound.Rules = append([]domain.FirewallRule{udp}, domain.FirewallRule{
		ID: "out", Name: "Out", Direction: domain.DirectionOutbound, Protocol: domain.ProtocolAny,
		Source: lanTarget(t, lan[0]), Destination: "198.51.100.0/24",
		Enabled: true,
	})
	install(t, g, withOutbound)
	assertPackets(t, g, "udp", 5)
	if forward := listRulesOrFail(t, g, filterTable, forwardChain); !containsFragment(forward, "tdrule:out") {
		t.Errorf("TUNNELDECK-FORWARD = %q, want the outbound rule", forward)
	}

	// Changing the rule itself rebuilds TUNNELDECK-INPUT, which resets
	// its counters.
	changedRule := withOutbound
	changedRule.Rules = []domain.FirewallRule{withOutbound.Rules[0], withOutbound.Rules[1]}
	changedRule.Rules[0].Source = tunSender.String()
	install(t, g, changedRule)
	assertPackets(t, g, "udp", 0)
	sendUDP(t, tun, 5000, 1)
	assertPackets(t, g, "udp", 1)

	input := listRulesOrFail(t, g, filterTable, inputChain)
	for _, line := range input[:len(input)-1] {
		if lineTag(line) == "" {
			t.Errorf("untagged line %q in %q", line, input)
		}
	}
	if input[len(input)-1] != "-A TUNNELDECK-INPUT -j DROP" {
		t.Errorf("TUNNELDECK-INPUT = %q, want the sealing DROP last", input)
	}
}

func install(t *testing.T, g *Guard, firewall domain.Firewall) {
	t.Helper()
	if err := g.InstallFirewall(context.Background(), firewall, 8080); err != nil {
		t.Fatalf("InstallFirewall: %v", err)
	}
}

func assertPackets(t *testing.T, g *Guard, id string, want uint64) {
	t.Helper()
	counters, available, err := g.RuleCounters(context.Background())
	if err != nil || !available {
		t.Fatalf("RuleCounters = %v, %v; want counters", available, err)
	}
	if got := counters[id].Packets; got != want {
		t.Errorf("packets of %s = %d, want %d (counters %v)", id, got, want, counters)
	}
}

// openTUN creates tdvpn0 as a TUN device without packet information; it
// exists while the returned file is open.
func openTUN(t *testing.T) *os.File {
	t.Helper()
	const (
		iffTUN    = 0x0001
		iffNoPI   = 0x1000
		tunSetIff = 0x400454ca
	)
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no TUN device (run the container with --device /dev/net/tun): %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })
	var request [40]byte
	copy(request[:16], DeviceName)
	binary.LittleEndian.PutUint16(request[16:], iffTUN|iffNoPI)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), tunSetIff, uintptr(unsafe.Pointer(&request[0]))); errno != 0 {
		t.Fatalf("TUNSETIFF: %v", errno)
	}
	return file
}

// sendUDP injects count UDP packets from tunSender to tunHost:port, each
// from its own source port so every one is a new connection.
func sendUDP(t *testing.T, tun *os.File, port, count int) {
	t.Helper()
	for i := range count {
		if _, err := tun.Write(udpPacket(tunSender, tunHost, 40000+i, port)); err != nil {
			t.Fatalf("write to TUN: %v", err)
		}
	}
}

// udpPacket is an IPv4 packet with an empty UDP datagram; UDP checksum 0
// means "none" in IPv4 (RFC 768).
func udpPacket(src, dst netip.Addr, srcPort, dstPort int) []byte {
	const headerLen, udpLen = 20, 8
	packet := make([]byte, headerLen+udpLen)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:], headerLen+udpLen)
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], src.AsSlice())
	copy(packet[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(packet[10:], ipChecksum(packet[:headerLen]))
	binary.BigEndian.PutUint16(packet[20:], uint16(srcPort))
	binary.BigEndian.PutUint16(packet[22:], uint16(dstPort))
	binary.BigEndian.PutUint16(packet[24:], udpLen)
	return packet
}

func ipChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i:]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
