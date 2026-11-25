package secret

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// KeyFileName is the name of the key file inside the data directory.
const KeyFileName = "secret.key"

// LoadOrCreateKey returns the encryption key.
//
// A non-empty envValue (TUNNELDECK_SECRET_KEY) wins and must be the standard
// base64 encoding of exactly KeySize bytes. Otherwise the key is read from
// <dataDir>/secret.key, which holds KeySize raw bytes; if that file does not
// exist it is created with random bytes, mode 0600, written atomically.
// A key file of the wrong length is an error and is never replaced, because
// a new key would make every stored secret unreadable.
func LoadOrCreateKey(dataDir, envValue string) ([]byte, error) {
	if envValue != "" {
		return decodeEnvKey(envValue)
	}
	path := filepath.Join(dataDir, KeyFileName)
	key, err := os.ReadFile(path)
	switch {
	case err == nil:
		return checkKeyFile(key, path)
	case errors.Is(err, fs.ErrNotExist):
		return createKeyFile(dataDir, path)
	default:
		return nil, fmt.Errorf("secret: read key file %s: %w", path, err)
	}
}

func decodeEnvKey(envValue string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(envValue))
	if err != nil {
		return nil, fmt.Errorf("%w: key from environment is not valid base64", ErrInvalidKey)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: key from environment decodes to %d bytes, want %d", ErrInvalidKey, len(key), KeySize)
	}
	return key, nil
}

func checkKeyFile(key []byte, path string) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf(
			"%w: key file %s has %d bytes, want %d; it is not replaced because a new key would make stored secrets unreadable",
			ErrInvalidKey, path, len(key), KeySize)
	}
	return key, nil
}

func createKeyFile(dataDir, path string) ([]byte, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("secret: create data directory: %w", err)
	}
	key := make([]byte, KeySize)
	// crypto/rand.Read never returns an error; it crashes the program if
	// the system random source fails.
	_, _ = rand.Read(key)
	if err := writeFileAtomic(path, key); err != nil {
		return nil, fmt.Errorf("secret: create key file %s: %w", path, err)
	}
	return key, nil
}

// writeFileAtomic writes data to a temp file (created with mode 0600) in the
// target directory, syncs it and renames it into place.
func writeFileAtomic(path string, data []byte) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}
