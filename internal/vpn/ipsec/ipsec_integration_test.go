//go:build integration && linux

// Smoke test of the driver against a real charon and a gateway with a
// pre-shared key, a virtual IP pool and the network 10.99.0.0/24 behind
// it: IKEv2, and IKEv1 Aggressive Mode with XAuth when
// TUNNELDECK_IPSEC_XAUTH_USER and TUNNELDECK_IPSEC_XAUTH_PASSWORD are set. It needs the TunnelDeck image (charon with kernel-libipsec),
// NET_ADMIN and /dev/net/tun; the test binary is built on the host:
//
//	GOOS=linux go test -c -tags integration -o ipsec.test ./internal/vpn/ipsec/
//	docker run --rm --cap-add NET_ADMIN --device /dev/net/tun --network <gateway's network> \
//	  -e TUNNELDECK_IPSEC_GATEWAY=<gateway address> -e TUNNELDECK_IPSEC_PSK=<key> \
//	  -v "$PWD/ipsec.test:/ipsec.test" --entrypoint /ipsec.test tunneldeck -test.run Integration -test.v

package ipsec

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/netguard"
)

func TestIntegrationVirtualIPTunnel(t *testing.T) {
	gateway, psk := os.Getenv("TUNNELDECK_IPSEC_GATEWAY"), os.Getenv("TUNNELDECK_IPSEC_PSK")
	if gateway == "" || psk == "" {
		t.Skip("TUNNELDECK_IPSEC_GATEWAY and TUNNELDECK_IPSEC_PSK name the test gateway")
	}
	t.Run("IKEv2", func(t *testing.T) {
		runTunnel(t, profileWith(map[string]any{KeyGateway: gateway}, map[string]string{SecretPSK: psk}))
	})
	user, password := os.Getenv("TUNNELDECK_IPSEC_XAUTH_USER"), os.Getenv("TUNNELDECK_IPSEC_XAUTH_PASSWORD")
	if user == "" {
		return
	}
	t.Run("IKEv1 XAuth", func(t *testing.T) {
		runTunnel(t, profileWith(map[string]any{
			KeyGateway: gateway, KeyIKEVersion: "ikev1", KeyXAuthUsername: user, KeyLocalID: user,
			KeyIKEProposals: []string{"aes256-sha512-modp2048"}, KeyESPProposals: []string{"aes256-sha512"},
		}, map[string]string{SecretPSK: psk, SecretXAuthPassword: password}))
	})
}

// runTunnel brings p up, pings through it, checks the counters and stops.
func runTunnel(t *testing.T, p domain.Profile) {
	ctx := context.Background()
	runner := netguard.ExecRunner{}
	d := New(Options{DeviceName: netguard.DeviceName, Runner: runner})
	mainBefore, rulesBefore := mustRunIP(t, runner, "route", "show", "table", "main"), mustRunIP(t, runner, "-4", "rule", "show")
	if err := d.Start(ctx, p, p.Secrets); err != nil {
		t.Fatalf("Start: %v", err)
	}
	up := awaitState(t, d, domain.StateConnected, 60*time.Second)
	t.Logf("connected: %+v", up)
	if got := mustRunIP(t, runner, "route", "show", "table", "main"); got != mainBefore {
		t.Errorf("charon changed the main table:\n%s\nwas\n%s", got, mainBefore)
	}
	if got := mustRunIP(t, runner, "-4", "rule", "show"); got != rulesBefore {
		t.Errorf("charon changed the routing rules:\n%s\nwas\n%s", got, rulesBefore)
	}
	if addresses := mustRunIP(t, runner, "-4", "-o", "addr", "show", "dev", netguard.DeviceName); !strings.Contains(addresses, up.VPNIP+"/32") {
		t.Errorf("tdvpn0 addresses = %q, want %s/32", addresses, up.VPNIP)
	}
	mustRunIP(t, runner, "route", "add", "10.99.0.0/24", "dev", netguard.DeviceName, "src", up.VPNIP)
	if _, err := runner.Run(ctx, "ping", "-c", "3", "-W", "2", "10.99.0.1"); err != nil {
		t.Errorf("ping through the tunnel: %v", err)
	}
	traffic := awaitTraffic(t, d)
	if traffic.BytesIn == 0 || traffic.BytesOut == 0 {
		t.Errorf("traffic = %+v, want bytes both ways", traffic)
	}
	stopCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := d.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if _, err := runner.Run(ctx, "ip", "link", "show", netguard.DeviceName); err == nil {
		t.Error("tdvpn0 outlived charon")
	}
	for _, name := range d.runtimeFiles() {
		if _, err := os.Stat(name); err == nil {
			t.Errorf("%s left behind", name)
		}
	}
}

func awaitState(t *testing.T, d *Driver, state domain.ConnectionState, limit time.Duration) domain.StateEvent {
	t.Helper()
	deadline := time.After(limit)
	for {
		select {
		case e, ok := <-d.Events():
			if !ok {
				t.Fatalf("the events ended before %s", state)
			}
			switch e := e.(type) {
			case domain.LogEvent:
				t.Logf("charon: %s %s", e.Level, e.Text)
			case domain.StateEvent:
				if e.State == state {
					return e
				}
				t.Fatalf("state %+v, want %s", e, state)
			}
		case <-deadline:
			t.Fatalf("no %s within %s", state, limit)
		}
	}
}

func awaitTraffic(t *testing.T, d *Driver) domain.TrafficEvent {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case e := <-d.Events():
			if traffic, ok := e.(domain.TrafficEvent); ok && traffic.BytesIn > 0 {
				return traffic
			}
		case <-deadline:
			t.Fatal("no traffic event with bytes")
		}
	}
}

func mustRunIP(t *testing.T, runner netguard.ExecRunner, args ...string) string {
	t.Helper()
	out, err := runner.Run(context.Background(), "ip", args...)
	if err != nil {
		t.Fatalf("ip %v: %v", args, err)
	}
	return out
}
