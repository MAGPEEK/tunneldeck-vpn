package vpn

import (
	"errors"
	"fmt"
	"slices"
	"sync"

	"tunneldeck/internal/domain"
)

// Factory creates a new, stopped driver instance.
type Factory func() Driver

// Registry maps protocols to driver factories. It is safe for concurrent
// use.
type Registry struct {
	mu        sync.RWMutex
	factories map[domain.Protocol]Factory
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{factories: make(map[domain.Protocol]Factory)}
}

// Register adds the factory for protocol. Registering a protocol twice
// fails with domain.ErrConflict.
func (r *Registry) Register(protocol domain.Protocol, factory Factory) error {
	if protocol == "" {
		return errors.New("register driver: protocol is empty")
	}
	if factory == nil {
		return fmt.Errorf("register driver %q: factory is nil", protocol)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.factories[protocol]; exists {
		return fmt.Errorf("register driver %q: %w", protocol, domain.ErrConflict)
	}
	r.factories[protocol] = factory
	return nil
}

// Protocols returns the registered protocols in ascending order.
func (r *Registry) Protocols() []domain.Protocol {
	r.mu.RLock()
	defer r.mu.RUnlock()
	protocols := make([]domain.Protocol, 0, len(r.factories))
	for protocol := range r.factories {
		protocols = append(protocols, protocol)
	}
	slices.Sort(protocols)
	return protocols
}

// Lookup returns the factory for protocol, or an error wrapping
// domain.ErrNotFound.
func (r *Registry) Lookup(protocol domain.Protocol) (Factory, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	factory, ok := r.factories[protocol]
	if !ok {
		return nil, fmt.Errorf("driver %q: %w", protocol, domain.ErrNotFound)
	}
	return factory, nil
}
