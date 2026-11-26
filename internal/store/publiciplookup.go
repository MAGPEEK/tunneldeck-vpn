package store

import "tunneldeck/internal/domain"

// PublicIPLookup returns the setting of the public IP detection.
func (s *Store) PublicIPLookup() domain.PublicIPLookup {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings.PublicIPLookup
}

// SetPublicIPLookup validates and stores the setting of the public IP
// detection.
func (s *Store) SetPublicIPLookup(settings domain.PublicIPLookup) error {
	if err := settings.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.settings.clone()
	next.PublicIPLookup = settings
	return s.commitSettings(next)
}
