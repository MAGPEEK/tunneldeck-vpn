package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/secret"
)

// secretValue is a recognisable secret that must never show up outside the
// encrypted file content and ProfileWithSecrets.
const secretValue = "TOP-SECRET-pa55w0rd"

var errInjected = errors.New("injected failure")

func newCipher(t *testing.T, fill byte) *secret.Cipher {
	t.Helper()
	c, err := secret.NewCipher(bytes.Repeat([]byte{fill}, secret.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// fakeClock returns increasing times in a non-UTC zone, one second apart.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	zone := time.FixedZone("CET", 3600)
	return &fakeClock{now: time.Date(2026, 11, 25, 10, 0, 0, 0, zone)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(time.Second)
	return c.now
}

func testDependencies(fsys fileSystem) dependencies {
	deps := defaultDependencies()
	deps.fs = fsys
	deps.now = newFakeClock().Now
	return deps
}

func openTestStore(t *testing.T, dir string, cipher Cipher) *Store {
	t.Helper()
	s, err := open(dir, cipher, testDependencies(osFileSystem{}))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return s
}

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	return openTestStore(t, dir, newCipher(t, 1)), dir
}

func openVPNProfile(name string) domain.Profile {
	settings := domain.Settings{}
	settings.SetString("remoteHost", "vpn.example.com")
	settings.SetInt("port", 1194)
	return domain.Profile{
		Name:     name,
		Protocol: domain.ProtocolOpenVPN,
		Settings: settings,
		Secrets:  map[string]string{"password": secretValue},
	}
}

func mustCreate(t *testing.T, s *Store, p domain.Profile) domain.PublicProfile {
	t.Helper()
	created, err := s.CreateProfile(p)
	if err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}
	return created
}

func readFile(t *testing.T, dir, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

func assertNoSecret(t *testing.T, what string, text string) {
	t.Helper()
	if strings.Contains(text, secretValue) {
		t.Fatalf("%s contains the secret value: %s", what, text)
	}
}

// faultyFS is the real file system with one injectable failing step:
// "mkdir", "read", "create", "write", "sync", "close" or "rename".
type faultyFS struct {
	osFileSystem
	failStep string
}

func (f *faultyFS) fails(step string) bool { return f.failStep == step }

func (f *faultyFS) MkdirAll(path string, perm os.FileMode) error {
	if f.fails("mkdir") {
		return errInjected
	}
	return f.osFileSystem.MkdirAll(path, perm)
}

func (f *faultyFS) ReadFile(name string) ([]byte, error) {
	if f.fails("read") {
		return nil, errInjected
	}
	return f.osFileSystem.ReadFile(name)
}

func (f *faultyFS) CreateTemp(dir, pattern string) (tempFile, error) {
	if f.fails("create") {
		return nil, errInjected
	}
	file, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	return &faultyFile{File: file, fs: f}, nil
}

func (f *faultyFS) Rename(oldPath, newPath string) error {
	if f.fails("rename") {
		return errInjected
	}
	return f.osFileSystem.Rename(oldPath, newPath)
}

type faultyFile struct {
	*os.File
	fs *faultyFS
}

func (f *faultyFile) Write(p []byte) (int, error) {
	if f.fs.fails("write") {
		return 0, errInjected
	}
	return f.File.Write(p)
}

func (f *faultyFile) Sync() error {
	if f.fs.fails("sync") {
		return errInjected
	}
	return f.File.Sync()
}

func (f *faultyFile) Close() error {
	err := f.File.Close()
	if f.fs.fails("close") {
		return errInjected
	}
	return err
}

// failingCipher wraps a real cipher and can fail encryption.
type failingCipher struct {
	*secret.Cipher
}

func (failingCipher) Encrypt(string) (string, error) { return "", errInjected }
