package store

import (
	"fmt"
	"sync"
	"time"
)

// Data file names and their current schema versions (SPEC §7, §13).
const (
	SettingsFileName = "settings.json"
	ProfilesFileName = "profiles.json"

	settingsSchemaVersion = 1
	profilesSchemaVersion = 1
)

// Cipher encrypts and decrypts secret values. *secret.Cipher implements it.
type Cipher interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(value string) (string, error)
}

// Store persists settings and profiles in the data directory. All methods
// are safe for concurrent use: one mutex serialises every operation, and a
// mutation updates memory only after its file was written. Reads return
// copies.
type Store struct {
	mu       sync.Mutex
	dir      string
	cipher   Cipher
	fs       fileSystem
	now      func() time.Time
	settings settingsDocument
	profiles profilesDocument
	docs     documentSpecs
}

type documentSpecs struct {
	settings documentSpec
	profiles documentSpec
}

// dependencies are the replaceable parts of a Store; tests swap them.
type dependencies struct {
	fs   fileSystem
	now  func() time.Time
	docs documentSpecs
}

func defaultDependencies() dependencies {
	return dependencies{
		fs:  osFileSystem{},
		now: time.Now,
		docs: documentSpecs{
			settings: documentSpec{SettingsFileName, settingsSchemaVersion, settingsMigrations},
			profiles: documentSpec{ProfilesFileName, profilesSchemaVersion, profilesMigrations},
		},
	}
}

// Open creates the data directory if needed and loads settings.json and
// profiles.json. Missing files yield defaults and are written on the first
// change. Open fails, without modifying any file, when a file is corrupted,
// has a newer schema version, or holds secrets the cipher cannot decrypt
// (wrong key).
func Open(dataDir string, cipher Cipher) (*Store, error) {
	return open(dataDir, cipher, defaultDependencies())
}

func open(dataDir string, cipher Cipher, deps dependencies) (*Store, error) {
	if err := deps.fs.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("store: create data directory: %w", err)
	}
	s := &Store{
		dir:      dataDir,
		cipher:   cipher,
		fs:       deps.fs,
		now:      deps.now,
		settings: defaultSettings(),
		profiles: defaultProfiles(),
		docs:     deps.docs,
	}
	if err := s.loadSettings(); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if err := s.loadProfiles(); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return s, nil
}

// timestamp returns the current time in UTC, as stored in data files.
func (s *Store) timestamp() time.Time {
	return s.now().UTC()
}
