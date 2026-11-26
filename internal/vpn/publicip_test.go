package vpn

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"tunneldeck/internal/domain"
)

// lookupResult is what fakeFinder answers to one lookup.
type lookupResult struct {
	ip  netip.Addr
	err error
}

// fakeFinder reports each lookup's local address on asked, then answers
// with the next value of results or ends with ctx, reporting that on
// cancelled.
type fakeFinder struct {
	enabled   atomic.Bool
	asked     chan netip.Addr
	results   chan lookupResult
	cancelled chan netip.Addr
}

func newFakeFinder(enabled bool) *fakeFinder {
	f := &fakeFinder{asked: make(chan netip.Addr, 8), results: make(chan lookupResult, 8), cancelled: make(chan netip.Addr, 8)}
	f.enabled.Store(enabled)
	return f
}

func (f *fakeFinder) Enabled() bool { return f.enabled.Load() }

func (f *fakeFinder) Lookup(ctx context.Context, local netip.Addr) (netip.Addr, error) {
	f.asked <- local
	select {
	case r := <-f.results:
		return r.ip, r.err
	case <-ctx.Done():
		f.cancelled <- local
		return netip.Addr{}, ctx.Err()
	}
}

func (f *fakeFinder) answer(ip string, err error) {
	result := lookupResult{err: err}
	if ip != "" {
		result.ip = netip.MustParseAddr(ip)
	}
	f.results <- result
}

func receive[T any](t *testing.T, what string, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(waitLimit):
		t.Fatalf("no %s", what)
		var zero T
		return zero
	}
}

func newPublicIPHarness(t *testing.T, finder *fakeFinder) *managerHarness {
	t.Helper()
	return newConfiguredHarness(t, defaultStart, func(cfg *ManagerConfig) { cfg.PublicIP = finder })
}

func (h *managerHarness) waitPublicIP(ip string) {
	h.t.Helper()
	h.events.next(h.t, "public IP "+ip, func(e domain.Event) bool {
		p, ok := e.(domain.PublicIPEvent)
		return ok && p.PublicIP == ip
	})
	if got := h.m.Status().PublicIP; got != ip {
		h.t.Fatalf("status public IP = %q, want %q", got, ip)
	}
}

func TestManagerDetectsThePublicIP(t *testing.T) {
	finder := newFakeFinder(true)
	h := newPublicIPHarness(t, finder)
	d := h.connectUp("a", "172.21.31.170")
	if local := receive(t, "lookup", finder.asked); local.String() != "172.21.31.170" {
		t.Fatalf("lookup from %s, want the VPN IP", local)
	}
	finder.answer("46.16.217.194", nil)
	h.waitLog("public IP through the tunnel: 46.16.217.194")
	h.waitPublicIP("46.16.217.194")

	// Reconnecting forgets it, since the next server may have another
	// address; the next connected event detects it again.
	d.emit(domain.StateEvent{State: domain.StateReconnecting})
	h.waitState(domain.StateReconnecting)
	h.waitPublicIP("")
	d.emit(connectedEvent("172.21.31.171"))
	if local := receive(t, "second lookup", finder.asked); local.String() != "172.21.31.171" {
		t.Fatalf("second lookup from %s", local)
	}
	finder.answer("", errors.New("ask api.ipify.org for the public IP: timeout"))
	h.waitLog("detecting the public IP through the tunnel failed: ask api.ipify.org for the public IP: timeout")
	if got := h.m.Status().PublicIP; got != "" {
		t.Errorf("public IP after a failed lookup = %q", got)
	}

	d.emit(connectedEvent("172.21.31.171"))
	receive(t, "third lookup", finder.asked)
	finder.answer("46.16.217.194", nil)
	h.waitPublicIP("46.16.217.194")
	if err := h.m.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	h.waitState(domain.StateDisconnected)
	if got := h.m.Status().PublicIP; got != "" {
		t.Errorf("public IP after disconnect = %q", got)
	}
}

func TestManagerCancelsThePublicIPLookup(t *testing.T) {
	tests := []struct {
		name string
		end  func(h *managerHarness, d *scriptedDriver)
	}{
		{name: "disconnect", end: func(h *managerHarness, _ *scriptedDriver) {
			if err := h.m.Disconnect(ctx); err != nil {
				h.t.Fatal(err)
			}
		}},
		{name: "tunnel reconnects", end: func(_ *managerHarness, d *scriptedDriver) {
			d.emit(domain.StateEvent{State: domain.StateReconnecting})
		}},
		{name: "tunnel fails", end: func(_ *managerHarness, d *scriptedDriver) {
			d.emit(errorEvent(domain.ErrorCodeProcessFailed, "exited"))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finder := newFakeFinder(true)
			h := newPublicIPHarness(t, finder)
			d := h.connectUp("a", "10.66.0.2")
			receive(t, "lookup", finder.asked)
			tt.end(h, d)
			receive(t, "cancelled lookup", finder.cancelled)
			h.m.Status()
			for _, e := range h.events.all() {
				if _, ok := e.(domain.PublicIPEvent); ok {
					t.Errorf("a cancelled lookup announced %+v", e)
				}
			}
			if got := h.m.Status().PublicIP; got != "" {
				t.Errorf("public IP = %q", got)
			}
		})
	}
}

func TestManagerPublicIPLookupSetting(t *testing.T) {
	finder := newFakeFinder(false)
	h := newPublicIPHarness(t, finder)
	h.connectUp("a", "10.66.0.2")
	h.m.Status()
	select {
	case local := <-finder.asked:
		t.Fatalf("lookup from %s while the detection is off", local)
	default:
	}

	finder.enabled.Store(true)
	h.m.PublicIPLookupChanged()
	receive(t, "lookup after switching on", finder.asked)
	finder.answer("203.0.113.9", nil)
	h.waitPublicIP("203.0.113.9")

	// A changed URL asks again; switching off forgets the address.
	h.m.PublicIPLookupChanged()
	receive(t, "lookup after a change", finder.asked)
	finder.enabled.Store(false)
	h.m.PublicIPLookupChanged()
	receive(t, "cancelled lookup", finder.cancelled)
	h.waitPublicIP("")
}

func TestManagerPublicIPLookupSettingWhileDisconnected(t *testing.T) {
	finder := newFakeFinder(true)
	h := newPublicIPHarness(t, finder)
	h.m.PublicIPLookupChanged()
	h.m.Status()
	select {
	case local := <-finder.asked:
		t.Fatalf("lookup from %s without a tunnel", local)
	default:
	}
}

func TestManagerDetectsThePublicIPOnceRouted(t *testing.T) {
	finder := newFakeFinder(true)
	h := newPublicIPHarness(t, finder)
	h.guard.set(func(g *fakeGuard) { g.routeErr = errors.New(failingRuleAdd) })
	h.connectUp("a", "10.66.0.2")
	h.m.PublicIPLookupChanged()
	h.m.Status()
	select {
	case local := <-finder.asked:
		t.Fatalf("lookup from %s before the routing applied", local)
	default:
	}

	h.guard.set(func(g *fakeGuard) { g.routeErr = nil })
	h.advance(2 * time.Second)
	h.waitLog("the tunnel routing is applied")
	receive(t, "lookup after the routing applied", finder.asked)
	finder.answer("203.0.113.9", nil)
	h.waitPublicIP("203.0.113.9")
}
