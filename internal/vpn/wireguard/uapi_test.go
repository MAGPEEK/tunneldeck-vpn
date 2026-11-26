package wireguard

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tunneldeck/internal/vpn"
)

func TestRenderConfig(t *testing.T) {
	p := validProfile(t, nil)
	c, problems := parseProfile(p, vpn.Secrets(p.Secrets), nil)
	if err := problems.OrNil(); err != nil {
		t.Fatal(err)
	}
	server := netip.MustParseAddrPort("198.51.100.23:51820")
	want := "private_key=" + rfcPrivateHex + "\n" +
		"replace_peers=true\n" +
		"public_key=" + bobPublicHex + "\n" +
		"preshared_key=0102030000000000000000000000000000000000000000000000000000000000\n" +
		"endpoint=198.51.100.23:51820\n" +
		"persistent_keepalive_interval=25\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=0.0.0.0/0\n" +
		"allowed_ip=10.20.0.0/16\n"
	if got := renderConfig(c, server); got != want {
		t.Errorf("renderConfig =\n%s\nwant\n%s", got, want)
	}

	c.presharedKey, c.keepalive = Key{}, 0
	ipv6 := netip.MustParseAddrPort("[2001:db8::1]:51820")
	got := renderConfig(c, ipv6)
	if want := "endpoint=[2001:db8::1]:51820\npersistent_keepalive_interval=0\n"; !strings.Contains(got, want) || strings.Contains(got, "preshared_key") {
		t.Errorf("renderConfig without PSK =\n%s", got)
	}
}

func TestRenderEndpointUpdate(t *testing.T) {
	got := renderEndpointUpdate(keyFromHex(t, bobPublicHex), netip.MustParseAddrPort("203.0.113.9:51821"))
	want := "public_key=" + bobPublicHex + "\nupdate_only=true\nendpoint=203.0.113.9:51821\n"
	if got != want {
		t.Errorf("renderEndpointUpdate =\n%s\nwant\n%s", got, want)
	}
}

func TestParsePeerStats(t *testing.T) {
	peer := keyFromHex(t, bobPublicHex)
	other := "public_key=" + rfcPublicHex + "\nlast_handshake_time_sec=99\nrx_bytes=99\ntx_bytes=99\n"
	tests := []struct {
		name    string
		dump    string
		want    peerStats
		wantErr bool
	}{
		{
			name: "after a handshake",
			dump: "private_key=" + rfcPrivateHex + "\nlisten_port=40000\n" + other +
				"public_key=" + bobPublicHex + "\npreshared_key=00\nprotocol_version=1\nendpoint=198.51.100.23:51820\n" +
				"last_handshake_time_sec=1795632744\nlast_handshake_time_nsec=500\ntx_bytes=1480\nrx_bytes=92\n" +
				"persistent_keepalive_interval=25\nallowed_ip=0.0.0.0/0\n",
			want: peerStats{lastHandshake: time.Unix(1795632744, 500), rxBytes: 92, txBytes: 1480},
		},
		{
			name: "before the first handshake",
			dump: "public_key=" + bobPublicHex + "\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\ntx_bytes=148\nrx_bytes=0\n",
			want: peerStats{txBytes: 148},
		},
		{name: "peer missing", dump: other, wantErr: true},
		{name: "bad counter", dump: "public_key=" + bobPublicHex + "\nrx_bytes=many\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePeerStats(tt.dump, peer)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, want error %v", err, tt.wantErr)
			}
			if !got.lastHandshake.Equal(tt.want.lastHandshake) || got.rxBytes != tt.want.rxBytes || got.txBytes != tt.want.txBytes {
				t.Errorf("stats = %+v, want %+v", got, tt.want)
			}
		})
	}
	if _, err := parsePeerStats("", peer); !errors.Is(err, errPeerMissing) {
		t.Errorf("empty dump = %v", err)
	}
}
