package netguard

import (
	"context"
	"errors"
	"slices"
	"testing"

	"tunneldeck/internal/domain"
)

const remotePort = 8443

const remoteAccept = "-p tcp --dport 8443 -m comment --comment tdfixed:remote-access -j ACCEPT"

// remoteInput is TUNNELDECK-INPUT of testFirewall with the remote-access
// accept before the DROP.
var remoteInput = slices.Concat(testInput[:len(testInput)-1], []string{remoteAccept, dropAll})

func installedGuard(t *testing.T, f *fakeRunner) *Guard {
	t.Helper()
	scriptFresh(f)
	g := newLegacyGuard(f)
	if err := g.InstallFirewall(context.Background(), testFirewall, uiPort); err != nil {
		t.Fatalf("install: %v", err)
	}
	f.takeCalls()
	return g
}

func TestSetRemoteAccessPortReinstallsAnInstalledFirewall(t *testing.T) {
	f := newFakeRunner()
	g := installedGuard(t, f)
	state := installedState{input: 1, forward: 1}

	scriptState(f, state)
	if err := g.SetRemoteAccessPort(context.Background(), remotePort); err != nil {
		t.Fatalf("open port: %v", err)
	}
	assertCalls(t, f.takeCalls(), reinstallCalls(state, remoteInput, testForward, nil, nil))

	scriptState(f, state)
	if err := g.SetRemoteAccessPort(context.Background(), 0); err != nil {
		t.Fatalf("close port: %v", err)
	}
	assertCalls(t, f.takeCalls(), reinstallCalls(state, testInput, testForward, nil, nil))
}

func TestAnyPortForwardKeepsTheRemoteAccessPortForTheHost(t *testing.T) {
	f := newFakeRunner()
	g := newLegacyGuard(f)
	if err := g.SetRemoteAccessPort(context.Background(), remotePort); err != nil {
		t.Fatalf("SetRemoteAccessPort: %v", err)
	}
	forward := rulesOnly(portForward(domain.ProtocolTCP, "192.168.2.5", domain.PortRange{}))
	state := installedState{input: 1, forward: 1}
	scriptState(f, state)
	if err := g.InstallFirewall(context.Background(), forward, uiPort); err != nil {
		t.Fatalf("install: %v", err)
	}
	input := inputWith(remoteAccept)
	accept := forwardWith(onRule(1, "-i tdvpn0 -d 192.168.2.5/32 -p tcp -m conntrack --ctstate DNAT -j ACCEPT"))
	dnat := onRule(1, "-p tcp -j DNAT --to-destination 192.168.2.5")
	masquerade := []string{onRule(1, "! -o tdvpn0 -d 192.168.2.5/32 -p tcp -m conntrack --ctstate DNAT -j MASQUERADE")}
	uiReturn := tagLine("tdfixed:host-port", "-p tcp --dport 8080 -j RETURN")
	assertCalls(t, f.takeCalls(), slices.Concat(detectInstall, reinstallCalls(state, input, accept,
		[]string{uiReturn, tagLine("tdfixed:host-port", "-p tcp --dport 8443 -j RETURN"), dnat}, masquerade)))

	scriptState(f, state)
	if err := g.SetRemoteAccessPort(context.Background(), 0); err != nil {
		t.Fatalf("close port: %v", err)
	}
	assertCalls(t, f.takeCalls(), reinstallCalls(state, inputWith(), accept,
		[]string{uiReturn, dnat}, masquerade))
}

func TestSetRemoteAccessPortBeforeInstallIsUsedByTheNextInstall(t *testing.T) {
	f := newFakeRunner()
	g := newLegacyGuard(f)
	if err := g.SetRemoteAccessPort(context.Background(), remotePort); err != nil {
		t.Fatalf("SetRemoteAccessPort: %v", err)
	}
	if calls := f.takeCalls(); len(calls) != 0 {
		t.Fatalf("commands without an installed firewall: %v", calls)
	}
	scriptFresh(f)
	if err := g.InstallFirewall(context.Background(), testFirewall, uiPort); err != nil {
		t.Fatalf("install: %v", err)
	}
	assertCalls(t, f.takeCalls(), freshCalls(remoteInput, testForward, nil, nil))
}

func TestSetRemoteAccessPortValidation(t *testing.T) {
	f := newFakeRunner()
	g := newLegacyGuard(f)
	for _, port := range []int{-1, 65536} {
		if err := g.SetRemoteAccessPort(context.Background(), port); !errors.Is(err, domain.ErrValidation) {
			t.Errorf("port %d: err = %v, want ErrValidation", port, err)
		}
	}
	scriptFresh(f)
	if err := g.InstallFirewall(context.Background(), testFirewall, uiPort); err != nil {
		t.Fatalf("install: %v", err)
	}
	f.takeCalls()
	for _, port := range []int{uiPort, 22} {
		if err := g.SetRemoteAccessPort(context.Background(), port); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("port %d: err = %v, want ErrValidation", port, err)
		}
	}
	if calls := f.takeCalls(); len(calls) != 0 {
		t.Fatalf("commands for a rejected port: %v", calls)
	}
	if g.remoteAccessPort != 0 {
		t.Errorf("a rejected port was kept: %d", g.remoteAccessPort)
	}
}

func TestInstallFirewallRejectsRemoteAccessConflicts(t *testing.T) {
	f := newFakeRunner()
	g := newLegacyGuard(f)
	if err := g.SetRemoteAccessPort(context.Background(), uiPort); err != nil {
		t.Fatalf("SetRemoteAccessPort before install: %v", err)
	}
	if err := g.InstallFirewall(context.Background(), domain.Firewall{}, uiPort); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("err = %v, want ErrValidation", err)
	}
	if err := g.SetRemoteAccessPort(context.Background(), remotePort); err != nil {
		t.Fatal(err)
	}
	forward := rulesOnly(changed(portForward(domain.ProtocolTCP, "192.168.2.2", domain.SinglePort(443)), func(r *domain.FirewallRule) {
		r.PublicPort = domain.SinglePort(remotePort)
	}))
	err := g.InstallFirewall(context.Background(), forward, uiPort)
	assertValidationField(t, err, "rules[0].publicPort")
	if calls := f.takeCalls(); len(calls) != 0 {
		t.Fatalf("commands for a rejected install: %v", calls)
	}
}

func TestRemoveFirewallForgetsTheInstallation(t *testing.T) {
	f := newFakeRunner()
	g := installedGuard(t, f)
	if err := g.RemoveFirewall(context.Background()); err != nil {
		t.Fatalf("remove: %v", err)
	}
	f.takeCalls()
	if err := g.SetRemoteAccessPort(context.Background(), remotePort); err != nil {
		t.Fatalf("SetRemoteAccessPort: %v", err)
	}
	if calls := f.takeCalls(); len(calls) != 0 {
		t.Fatalf("commands after the firewall was removed: %v", calls)
	}
}

func TestSetRemoteAccessPortReportsAFailedReinstall(t *testing.T) {
	f := newFakeRunner()
	g := installedGuard(t, f)
	scriptInstalled(f)
	f.on(legacy+"-A TUNNELDECK-INPUT "+remoteAccept, fail(noPermission))
	if err := g.SetRemoteAccessPort(context.Background(), remotePort); err == nil {
		t.Fatal("SetRemoteAccessPort succeeded despite a failing command")
	}
	if calls := f.takeCalls(); !slices.Contains(calls, legacy+"-A TUNNELDECK-INPUT "+remoteAccept) {
		t.Errorf("the port was not opened: %v", calls)
	}
}
