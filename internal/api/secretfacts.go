package api

import (
	"maps"
	"slices"
	"sync"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

// secretFacts is what a driver computes from a profile's secrets for
// display: the advisories that judge secret values and the derived values,
// such as WireGuard's public key. It never holds a secret value.
type secretFacts struct {
	advisories []vpn.Advisory
	derived    map[string]string
}

// clone returns a copy that shares nothing with f, so a caller cannot
// change a cached entry.
func (f secretFacts) clone() secretFacts {
	return secretFacts{advisories: slices.Clone(f.advisories), derived: maps.Clone(f.derived)}
}

// secretFactsCache keeps the secretFacts of each profile, so listing and
// reading profiles and the connection status do not decrypt secrets on
// every request. The profile handlers invalidate an entry after each
// change. An entry also records the UpdatedAt of the profile it was
// computed from and only matches that revision, so a change made past the
// handlers is noticed too. The cache starts empty: after a restart or a
// migration each profile is computed again on its first read.
type secretFactsCache struct {
	mu      sync.Mutex
	entries map[string]secretFactsEntry
	// generation counts invalidations. A computation that began before an
	// invalidation may have read the old secrets and is not stored.
	generation uint64
}

type secretFactsEntry struct {
	updatedAt time.Time
	facts     secretFacts
}

func newSecretFactsCache() *secretFactsCache {
	return &secretFactsCache{entries: map[string]secretFactsEntry{}}
}

// lookup returns the facts of profile id at revision updatedAt. On a miss
// it returns the generation to pass to store.
func (c *secretFactsCache) lookup(id string, updatedAt time.Time) (facts secretFacts, generation uint64, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, found := c.entries[id]
	if !found || !entry.updatedAt.Equal(updatedAt) {
		return secretFacts{}, c.generation, false
	}
	return entry.facts.clone(), c.generation, true
}

// store keeps facts computed from profile id at revision updatedAt, unless
// an invalidation happened since lookup returned generation.
func (c *secretFactsCache) store(id string, updatedAt time.Time, facts secretFacts, generation uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if generation != c.generation {
		return
	}
	c.entries[id] = secretFactsEntry{updatedAt: updatedAt, facts: facts.clone()}
}

// invalidate drops the entry of profile id; call it after the profile was
// changed or deleted.
func (c *secretFactsCache) invalidate(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, id)
	c.generation++
}

// secretFacts returns the facts driver d computes from the stored secrets
// of p. It decrypts the secrets only when d judges or derives anything and
// the cache holds no entry for p's revision; a missing profile yields none.
func (s *Server) secretFacts(d vpn.Driver, p domain.PublicProfile) secretFacts {
	adviser, advises := d.(secretAdviser)
	values, derives := d.(deriver)
	if !advises && !derives {
		return secretFacts{}
	}
	cached, generation, ok := s.facts.lookup(p.ID, p.UpdatedAt)
	if ok {
		return cached
	}
	stored, err := s.deps.Profiles.ProfileWithSecrets(p.ID)
	if err != nil {
		return secretFacts{}
	}
	var facts secretFacts
	if advises {
		facts.advisories = adviser.AdviseSecrets(stored)
	}
	if derives {
		facts.derived = values.Derive(stored)
	}
	s.facts.store(stored.ID, stored.UpdatedAt, facts, generation)
	return facts
}
