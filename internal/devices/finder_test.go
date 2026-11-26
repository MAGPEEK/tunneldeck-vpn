package devices

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"tunneldeck/internal/domain"
)

type fakeNeighbours struct {
	devices []domain.LANDevice
	err     error
}

func (f fakeNeighbours) LANNeighbours(context.Context) ([]domain.LANDevice, error) {
	return slices.Clone(f.devices), f.err
}

// fakeResolver answers from names; addresses in block wait until the
// lookup's context ends, or forever when ignoreDeadline is set.
type fakeResolver struct {
	names          map[string]string
	block          map[string]bool
	ignoreDeadline bool

	mu      sync.Mutex
	lookups []string
}

func (r *fakeResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	r.mu.Lock()
	r.lookups = append(r.lookups, addr)
	r.mu.Unlock()
	if r.block[addr] {
		if r.ignoreDeadline {
			select {}
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if name, ok := r.names[addr]; ok {
		return []string{name}, nil
	}
	return nil, errors.New("no PTR record")
}

func (r *fakeResolver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.lookups)
}

func lanDevice(addr string) domain.LANDevice {
	return domain.LANDevice{Address: netip.MustParseAddr(addr), MAC: "3c:a6:2f:00:00:01", State: "REACHABLE", OnLAN: true}
}

func names(devices []domain.LANDevice) []string {
	out := make([]string, len(devices))
	for i, d := range devices {
		out[i] = d.Name + "@" + d.Address.String()
	}
	return out
}

func TestDevicesAreNamedAndSorted(t *testing.T) {
	neighbours := fakeNeighbours{devices: []domain.LANDevice{
		lanDevice("192.168.2.30"), lanDevice("192.168.2.4"), lanDevice("192.168.2.1"),
		lanDevice("192.168.2.20"), lanDevice("192.168.2.10"),
	}}
	resolver := &fakeResolver{names: map[string]string{
		"192.168.2.30": "nas.fritz.box.", "192.168.2.1": "fritz.box.", "192.168.2.10": "Laptop.fritz.box.",
	}}
	got, err := New(neighbours, resolver, time.Now).Devices(context.Background())
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}
	want := []string{"fritz.box@192.168.2.1", "Laptop.fritz.box@192.168.2.10", "nas.fritz.box@192.168.2.30",
		"@192.168.2.4", "@192.168.2.20"}
	if !slices.Equal(names(got), want) {
		t.Errorf("devices = %v, want %v", names(got), want)
	}
}

func TestNameLookupIsBoundedByTheTimeout(t *testing.T) {
	for _, ignore := range []bool{false, true} {
		neighbours := fakeNeighbours{devices: []domain.LANDevice{lanDevice("192.168.2.1"), lanDevice("192.168.2.2")}}
		resolver := &fakeResolver{
			names:          map[string]string{"192.168.2.1": "fritz.box."},
			block:          map[string]bool{"192.168.2.2": true},
			ignoreDeadline: ignore,
		}
		start := time.Now()
		got, err := New(neighbours, resolver, time.Now).Devices(context.Background())
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("Devices: %v", err)
		}
		if elapsed > LookupTimeout+500*time.Millisecond {
			t.Errorf("ignoreDeadline=%v: took %v, want at most about %v", ignore, elapsed, LookupTimeout)
		}
		if want := []string{"fritz.box@192.168.2.1", "@192.168.2.2"}; !slices.Equal(names(got), want) {
			t.Errorf("ignoreDeadline=%v: devices = %v, want %v", ignore, names(got), want)
		}
	}
}

func TestNamesAreCached(t *testing.T) {
	now := time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	neighbours := fakeNeighbours{devices: []domain.LANDevice{lanDevice("192.168.2.1"), lanDevice("192.168.2.2")}}
	resolver := &fakeResolver{names: map[string]string{"192.168.2.1": "fritz.box."}}
	finder := New(neighbours, resolver, clock)
	for range 2 {
		if _, err := finder.Devices(context.Background()); err != nil {
			t.Fatalf("Devices: %v", err)
		}
	}
	if n := resolver.count(); n != 2 {
		t.Errorf("lookups within the cache time = %d, want 2 (a missing name is cached too)", n)
	}
	mu.Lock()
	now = now.Add(CacheTTL)
	mu.Unlock()
	got, err := finder.Devices(context.Background())
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}
	if n := resolver.count(); n != 4 {
		t.Errorf("lookups after the cache time = %d, want 4", n)
	}
	if got[0].Name != "fritz.box" {
		t.Errorf("devices = %v", names(got))
	}
}

func TestDevicesNeighbourFailure(t *testing.T) {
	_, err := New(fakeNeighbours{err: errors.New("ip failed")}, &fakeResolver{}, time.Now).Devices(context.Background())
	if err == nil {
		t.Fatal("Devices succeeded although the neighbours could not be listed")
	}
}
