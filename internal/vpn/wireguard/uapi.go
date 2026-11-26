package wireguard

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// This file speaks the cross-platform configuration protocol of WireGuard
// (https://www.wireguard.com/xplatform/#configuration-protocol), which
// wireguard-go serves in process through IpcSet and IpcGet.

// renderConfig returns the UAPI "set" operation that configures the device
// for c: its private key and the server, reached at server, as its only
// peer. No listen port is set, so the device picks a free one.
func renderConfig(c profileConfig, server netip.AddrPort) string {
	var b uapiBuilder
	b.set("private_key", c.privateKey.hex())
	b.set("replace_peers", "true")
	b.set("public_key", c.peerPublicKey.hex())
	if !c.presharedKey.isZero() {
		b.set("preshared_key", c.presharedKey.hex())
	}
	b.set("endpoint", server.String())
	b.set("persistent_keepalive_interval", strconv.Itoa(c.keepalive))
	b.set("replace_allowed_ips", "true")
	for _, prefix := range c.allowedIPs {
		b.set("allowed_ip", prefix.String())
	}
	return b.String()
}

// renderEndpointUpdate returns the UAPI "set" operation that points the
// existing peer at server, as wireguard-tools' reresolve-dns does.
func renderEndpointUpdate(peer Key, server netip.AddrPort) string {
	var b uapiBuilder
	b.set("public_key", peer.hex())
	b.set("update_only", "true")
	b.set("endpoint", server.String())
	return b.String()
}

// uapiBuilder writes key=value lines.
type uapiBuilder struct{ strings.Builder }

func (b *uapiBuilder) set(key, value string) {
	b.WriteString(key)
	b.WriteByte('=')
	b.WriteString(value)
	b.WriteByte('\n')
}

// peerStats is what the UAPI "get" operation reports about the server.
type peerStats struct {
	// lastHandshake is zero until the first handshake.
	lastHandshake time.Time
	rxBytes       uint64
	txBytes       uint64
}

var errPeerMissing = errors.New("the server is not configured on the device")

// parsePeerStats reads the stats of the peer with public key peer from the
// output of a "get" operation.
func parsePeerStats(dump string, peer Key) (peerStats, error) {
	var stats peerStats
	var seconds, nanos int64
	found, current := false, false
	scanner := bufio.NewScanner(strings.NewReader(dump))
	for scanner.Scan() {
		key, value, _ := strings.Cut(scanner.Text(), "=")
		if key == "public_key" {
			current = value == peer.hex()
			found = found || current
			continue
		}
		if !current {
			continue
		}
		var err error
		switch key {
		case "last_handshake_time_sec":
			seconds, err = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			nanos, err = strconv.ParseInt(value, 10, 64)
		case "rx_bytes":
			stats.rxBytes, err = strconv.ParseUint(value, 10, 64)
		case "tx_bytes":
			stats.txBytes, err = strconv.ParseUint(value, 10, 64)
		}
		if err != nil {
			return peerStats{}, fmt.Errorf("read the device state: %s: %w", key, err)
		}
	}
	if !found {
		return peerStats{}, errPeerMissing
	}
	if seconds != 0 || nanos != 0 {
		stats.lastHandshake = time.Unix(seconds, nanos)
	}
	return stats, nil
}
