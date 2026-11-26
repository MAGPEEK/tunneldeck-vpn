// Package devices lists the LAN devices the firewall editor offers in its
// device picker (SPEC §16.4): the host's LAN neighbours with the names
// reverse DNS knows for them.
package devices

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"tunneldeck/internal/domain"
)

// Limits of the name lookup: all lookups of one listing together take at
// most LookupTimeout, and every answer, a missing name included, is kept
// for CacheTTL.
const (
	LookupTimeout = time.Second
	CacheTTL      = 5 * time.Minute
)

// Neighbours lists the host's LAN neighbours without names;
// *netguard.Guard implements it.
type Neighbours interface {
	LANNeighbours(ctx context.Context) ([]domain.LANDevice, error)
}

// Resolver looks up the names of an address; *net.Resolver implements it.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// Finder combines the neighbours with their reverse-DNS names. It is safe
// for concurrent use.
type Finder struct {
	neighbours Neighbours
	resolver   Resolver
	now        func() time.Time

	mu    sync.Mutex
	cache map[netip.Addr]cachedName
}

type cachedName struct {
	name    string
	expires time.Time
}

// New returns a Finder; now is the clock of the name cache.
func New(neighbours Neighbours, resolver Resolver, now func() time.Time) *Finder {
	return &Finder{neighbours: neighbours, resolver: resolver, now: now, cache: make(map[netip.Addr]cachedName)}
}

// Devices returns the LAN neighbours, named where reverse DNS answered in
// time, sorted by name (unnamed last), then address.
func (f *Finder) Devices(ctx context.Context) ([]domain.LANDevice, error) {
	devices, err := f.neighbours.LANNeighbours(ctx)
	if err != nil {
		return nil, fmt.Errorf("list LAN devices: %w", err)
	}
	f.name(ctx, devices)
	slices.SortFunc(devices, compareDevices)
	return devices, nil
}

// name fills in the cached names and looks up the others concurrently.
// The lookups share a deadline of LookupTimeout, and it returns by then
// even if the resolver ignores the deadline.
func (f *Finder) name(ctx context.Context, devices []domain.LANDevice) {
	ctx, cancel := context.WithTimeout(ctx, LookupTimeout)
	defer cancel()
	type answer struct {
		index int
		name  string
	}
	answers := make(chan answer, len(devices))
	pending := 0
	for i, device := range devices {
		if name, ok := f.cached(device.Address); ok {
			devices[i].Name = name
			continue
		}
		pending++
		go func() { answers <- answer{index: i, name: f.lookup(ctx, device.Address)} }()
	}
	for ; pending > 0; pending-- {
		select {
		case a := <-answers:
			devices[a.index].Name = a.name
		case <-ctx.Done():
			return
		}
	}
}

func (f *Finder) cached(addr netip.Addr) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	entry, ok := f.cache[addr]
	if !ok || !f.now().Before(entry.expires) {
		return "", false
	}
	return entry.name, true
}

// lookup resolves addr and caches the first name without its trailing
// dot; a failed or timed-out lookup is cached as "no name".
func (f *Finder) lookup(ctx context.Context, addr netip.Addr) string {
	var name string
	if names, err := f.resolver.LookupAddr(ctx, addr.String()); err == nil && len(names) > 0 {
		name = strings.TrimSuffix(names[0], ".")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	for cachedAddr, entry := range f.cache {
		if !now.Before(entry.expires) {
			delete(f.cache, cachedAddr)
		}
	}
	f.cache[addr] = cachedName{name: name, expires: now.Add(CacheTTL)}
	return name
}

func compareDevices(a, b domain.LANDevice) int {
	switch {
	case a.Name == "" && b.Name != "":
		return 1
	case a.Name != "" && b.Name == "":
		return -1
	}
	return cmp.Or(cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)), a.Address.Compare(b.Address))
}
