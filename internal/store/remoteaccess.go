package store

import (
	"fmt"

	"tunneldeck/internal/domain"
)

// remoteAccessRecord is the remoteAccess object of settings.json: the
// setting plus one certificate slot per source, so switching the source
// keeps the other certificate.
type remoteAccessRecord struct {
	domain.RemoteAccess
	SelfSigned *keyPairRecord `json:"selfSignedCertificate,omitempty"`
	Uploaded   *keyPairRecord `json:"uploadedCertificate,omitempty"`
}

// keyPairRecord is a stored certificate; KeyPEM is encrypted (enc:v1).
type keyPairRecord struct {
	CertificatePEM string `json:"certificatePem"`
	KeyPEM         string `json:"keyPem"`
}

// slot returns the certificate slot of source.
func (r *remoteAccessRecord) slot(source domain.CertificateSource) **keyPairRecord {
	if source == domain.CertificateUploaded {
		return &r.Uploaded
	}
	return &r.SelfSigned
}

// checkRemoteAccess fills defaults for missing values, validates the
// setting and fails early when a stored key cannot be decrypted.
func (s *Store) checkRemoteAccess(r *remoteAccessRecord) error {
	defaults := domain.DefaultRemoteAccess()
	if r.Port == 0 {
		r.Port = defaults.Port
	}
	if r.CertificateSource == "" {
		r.CertificateSource = defaults.CertificateSource
	}
	if err := r.Validate(); err != nil {
		return fmt.Errorf("%s is corrupted: remoteAccess: %w", SettingsFileName, err)
	}
	for _, source := range []domain.CertificateSource{domain.CertificateSelfSigned, domain.CertificateUploaded} {
		record := *r.slot(source)
		if record == nil {
			continue
		}
		if _, err := s.cipher.Decrypt(record.KeyPEM); err != nil {
			return fmt.Errorf("%s: remoteAccess, %s certificate key: %w", SettingsFileName, source, err)
		}
	}
	return nil
}

// RemoteAccess returns the remote-access setting.
func (s *Store) RemoteAccess() domain.RemoteAccess {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings.RemoteAccess.RemoteAccess
}

// SetRemoteAccess validates and stores the remote-access setting. The
// certificates are kept.
func (s *Store) SetRemoteAccess(settings domain.RemoteAccess) error {
	if err := settings.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.settings.clone()
	next.RemoteAccess.RemoteAccess = settings
	return s.commitSettings(next)
}

// RemoteAccessCertificate returns the PEM certificate chain stored for
// source, without its key.
func (s *Store) RemoteAccessCertificate(source domain.CertificateSource) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record := *s.settings.RemoteAccess.slot(source)
	if record == nil {
		return "", false
	}
	return record.CertificatePEM, true
}

// RemoteAccessKeyPair returns the certificate stored for source with its
// decrypted key, for the HTTPS listener only. Never hand the key to a
// client.
func (s *Store) RemoteAccessKeyPair(source domain.CertificateSource) (domain.KeyPair, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record := *s.settings.RemoteAccess.slot(source)
	if record == nil {
		return domain.KeyPair{}, false, nil
	}
	key, err := s.cipher.Decrypt(record.KeyPEM)
	if err != nil {
		return domain.KeyPair{}, false, fmt.Errorf("store: remote-access %s certificate key: %w", source, err)
	}
	return domain.KeyPair{CertificatePEM: record.CertificatePEM, KeyPEM: key}, true, nil
}

// SetRemoteAccessKeyPair stores the certificate of source, its key
// encrypted. Checking that the pair is usable is the caller's job.
func (s *Store) SetRemoteAccessKeyPair(source domain.CertificateSource, pair domain.KeyPair) error {
	if !source.Valid() {
		return domain.NewValidationError("certificateSource", "must be selfSigned or uploaded")
	}
	if pair.CertificatePEM == "" || pair.KeyPEM == "" {
		return domain.NewValidationError("certificate", "certificate and key are required")
	}
	key, err := s.cipher.Encrypt(pair.KeyPEM)
	if err != nil {
		return fmt.Errorf("store: encrypt remote-access key: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.settings.clone()
	*next.RemoteAccess.slot(source) = &keyPairRecord{CertificatePEM: pair.CertificatePEM, KeyPEM: key}
	return s.commitSettings(next)
}
