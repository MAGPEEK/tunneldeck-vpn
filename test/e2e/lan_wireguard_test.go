//go:build e2e

package e2e

import (
	"net/http"
	"testing"
	"time"
)

// checkKillSwitchOverWireGuard runs the kill-switch case over a WireGuard
// tunnel to server-wg. The driver counts a tunnel as lost only after 180 s
// without a handshake (SPEC §18) and keeps tdvpn0 meanwhile, so the case
// simulates the loss instead of waiting: first the server's device goes
// down, a dead tunnel that still holds tdvpn0, then TunnelDeck's own
// device disappears, so the driver fails, the manager retries and lan-web's
// traffic finds no tunnel route at all.
func (sc *lanScenario) checkKillSwitchOverWireGuard(t *testing.T) {
	wg := newWireGuardScenario(sc.stack, sc.td)
	keys := wg.newPeer(t)
	id := sc.td.createProfile(t, wg.formProfile(keys, wg.serverPublicKey(t), everything))
	t.Cleanup(func() {
		_ = sc.td.api.call(http.MethodPost, "/api/connection/disconnect", nil, nil)
		_ = sc.td.setFirewallRules(nil)
		_ = sc.td.api.call(http.MethodDelete, "/api/profiles/"+id, nil, nil)
	})
	ws := &lanScenario{scenario: wg.scenario, host: sc.host}
	ws.vpnIP = wg.connect(t, id)
	ws.checkKillSwitchWith(t, ws.dropWireGuardTunnel, ws.restoreWireGuardTunnel)
}

// dropWireGuardTunnel takes server-wg's device down: the tunnel is dead,
// yet the state stays connected and tdvpn0 stays, so nothing leaks. Then
// TunnelDeck's tdvpn0 is deleted: the driver reports the device's end and
// the state leaves connected while the server stays down.
func (sc *lanScenario) dropWireGuardTunnel(t *testing.T) {
	t.Helper()
	sc.stack.exec(t, wireGuardService, "ip", "link", "set", "wg0", "down")
	t.Cleanup(func() { _, _ = sc.stack.tryExec(wireGuardService, "ip", "link", "set", "wg0", "up") })
	sc.expectKillSwitch(t, "while the server is down")
	sc.expectNoForward(t, "while the server is down")
	if status := sc.td.status(t); status.State != "connected" {
		t.Errorf("state %s while the server is down, want connected (lost only after 180 s without a handshake)", status.State)
	}

	sc.td.exec(t, "ip", "link", "delete", "tdvpn0")
	sc.td.waitFor(t, "the tunnel to drop", 30*time.Second, func(s connectionStatus) bool { return s.State != "connected" })
}

// restoreWireGuardTunnel brings server-wg's device up and waits for the
// handshake of the tunnel the manager started again.
func (sc *lanScenario) restoreWireGuardTunnel(t *testing.T) {
	t.Helper()
	sc.stack.exec(t, wireGuardService, "ip", "link", "set", "wg0", "up")
	sc.vpnIP = sc.waitConnected(t)
}
