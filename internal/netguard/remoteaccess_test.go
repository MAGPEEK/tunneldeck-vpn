package netguard

import (
	"context"
	"errors"
	"slices"
	"testing"

	"tunneldeck/internal/domain"
)

const remotePort = 8443

// reinstallInputCalls is the TUNNELDECK-INPUT refill for testRules over the
// state scriptInstalled describes, with extra accepts before the DROP.
func reinstallInputCalls(extra ...string) []string {
	lines := []string{
		"-S TUNNELDECK-INPUT",
		"-S INPUT",
		"-A TUNNELDECK-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-A TUNNELDECK-INPUT -p tcp --dport 22 -j ACCEPT",
		"-A TUNNELDECK-INPUT -p udp --dport 51820 -s 192.168.1.0/24 -j ACCEPT",
	}
	lines = append(lines, extra...)
	lines = append(lines, "-A TUNNELDECK-INPUT -j DROP",
		"-D TUNNELDECK-INPUT 1", "-D TUNNELDECK-INPUT 1", "-D TUNNELDECK-INPUT 1", "-D TUNNELDECK-INPUT 1")
	return prefixed(legacy, lines...)
}

func TestSetRemoteAccessPortReinstallsAnInstalledFirewall(t *testing.T) {
	f := newFakeRunner()
	scriptFresh(f)
	g := New(f)
	if err := g.InstallFirewall(context.Background(), testRules, uiPort); err != nil {
		t.Fatalf("install: %v", err)
	}
	f.takeCalls()

	scriptInstalled(f)
	if err := g.SetRemoteAccessPort(context.Background(), remotePort); err != nil {
		t.Fatalf("open port: %v", err)
	}
	assertCalls(t, f.takeCalls(), slices.Concat(
		reinstallInputCalls("-A TUNNELDECK-INPUT -p tcp --dport 8443 -j ACCEPT"), reinstallForwardCalls))

	scriptInstalled(f)
	if err := g.SetRemoteAccessPort(context.Background(), 0); err != nil {
		t.Fatalf("close port: %v", err)
	}
	assertCalls(t, f.takeCalls(), slices.Concat(reinstallInputCalls(), reinstallForwardCalls))
}

func TestSetRemoteAccessPortBeforeInstallIsUsedByTheNextInstall(t *testing.T) {
	f := newFakeRunner()
	g := New(f)
	if err := g.SetRemoteAccessPort(context.Background(), remotePort); err != nil {
		t.Fatalf("SetRemoteAccessPort: %v", err)
	}
	if calls := f.takeCalls(); len(calls) != 0 {
		t.Fatalf("commands without an installed firewall: %v", calls)
	}
	scriptFresh(f)
	if err := g.InstallFirewall(context.Background(), testRules, uiPort); err != nil {
		t.Fatalf("install: %v", err)
	}
	want := slices.Concat(detectLegacy, freshInputCalls, freshForwardCalls)
	accept := legacy + "-A TUNNELDECK-INPUT -p tcp --dport 8443 -j ACCEPT"
	finalDrop := slices.Index(want, legacy+"-D TUNNELDECK-INPUT 1") - 1
	want = slices.Insert(want, finalDrop, accept)
	assertCalls(t, f.takeCalls(), want)
}

func TestSetRemoteAccessPortValidation(t *testing.T) {
	f := newFakeRunner()
	scriptFresh(f)
	g := New(f)
	for _, port := range []int{-1, 65536} {
		if err := g.SetRemoteAccessPort(context.Background(), port); !errors.Is(err, domain.ErrValidation) {
			t.Errorf("port %d: err = %v, want ErrValidation", port, err)
		}
	}
	if err := g.InstallFirewall(context.Background(), testRules, uiPort); err != nil {
		t.Fatalf("install: %v", err)
	}
	f.takeCalls()
	if err := g.SetRemoteAccessPort(context.Background(), uiPort); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("UI port: err = %v, want ErrValidation", err)
	}
	if calls := f.takeCalls(); len(calls) != 0 {
		t.Fatalf("commands for a rejected port: %v", calls)
	}
}

func TestInstallFirewallRejectsRemoteAccessOnTheUIPort(t *testing.T) {
	f := newFakeRunner()
	g := New(f)
	if err := g.SetRemoteAccessPort(context.Background(), uiPort); err != nil {
		t.Fatalf("SetRemoteAccessPort before install: %v", err)
	}
	if err := g.InstallFirewall(context.Background(), nil, uiPort); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("err = %v, want ErrValidation", err)
	}
	if calls := f.takeCalls(); len(calls) != 0 {
		t.Fatalf("commands for a rejected install: %v", calls)
	}
}

func TestRemoveFirewallForgetsTheInstallation(t *testing.T) {
	f := newFakeRunner()
	scriptFresh(f)
	g := New(f)
	if err := g.InstallFirewall(context.Background(), testRules, uiPort); err != nil {
		t.Fatalf("install: %v", err)
	}
	f.on(legacy+"-C INPUT -i tdvpn0 -j TUNNELDECK-INPUT", fail(badRule)).
		on(legacy+"-C FORWARD -i tdvpn0 -j TUNNELDECK-FORWARD", fail(badRule)).
		on(legacy+"-C FORWARD -o tdvpn0 -j TUNNELDECK-FORWARD", fail(badRule))
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
	scriptFresh(f)
	g := New(f)
	if err := g.InstallFirewall(context.Background(), testRules, uiPort); err != nil {
		t.Fatalf("install: %v", err)
	}
	scriptInstalled(f)
	f.on(legacy+"-A TUNNELDECK-INPUT -p tcp --dport 8443 -j ACCEPT", fail(noPermission))
	if err := g.SetRemoteAccessPort(context.Background(), remotePort); err == nil {
		t.Fatal("SetRemoteAccessPort succeeded despite a failing command")
	}
}
