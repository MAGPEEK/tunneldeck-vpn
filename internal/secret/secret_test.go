package secret

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const plaintext = "correct horse battery staple"

func newTestCipher(t *testing.T, fill byte) *Cipher {
	t.Helper()
	c, err := NewCipher(bytes.Repeat([]byte{fill}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewCipherRejectsWrongKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := NewCipher(make([]byte, n)); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("NewCipher(%d bytes) err = %v, want ErrInvalidKey", n, err)
		}
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	c := newTestCipher(t, 1)
	for _, input := range []string{plaintext, "", "ünïcödé", strings.Repeat("x", 10000)} {
		encrypted, err := c.Encrypt(input)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(encrypted, Prefix) {
			t.Fatalf("Encrypt result %q lacks prefix", encrypted)
		}
		if input != "" && strings.Contains(encrypted, input) {
			t.Fatalf("Encrypt result contains the plaintext")
		}
		got, err := c.Decrypt(encrypted)
		if err != nil || got != input {
			t.Fatalf("Decrypt = %q, %v; want %q", got, err, input)
		}
	}
}

func TestEncryptUsesFreshNonce(t *testing.T) {
	c := newTestCipher(t, 1)
	a, _ := c.Encrypt(plaintext)
	b, _ := c.Encrypt(plaintext)
	if a == b {
		t.Fatal("two encryptions of the same plaintext are equal")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(a, Prefix))
	if err != nil {
		t.Fatal(err)
	}
	if want := 12 + len(plaintext) + 16; len(raw) != want {
		t.Fatalf("sealed length = %d, want nonce(12)+plaintext+tag(16) = %d", len(raw), want)
	}
}

func TestDecryptErrors(t *testing.T) {
	c := newTestCipher(t, 1)
	valid, _ := c.Encrypt(plaintext)
	otherKey, _ := newTestCipher(t, 2).Encrypt(plaintext)

	tests := []struct {
		name    string
		value   string
		wantErr error
	}{
		{"missing prefix", plaintext, ErrMalformed},
		{"other version prefix", "enc:v2:" + strings.TrimPrefix(valid, Prefix), ErrMalformed},
		{"empty", "", ErrMalformed},
		{"invalid base64", Prefix + "!!!", ErrMalformed},
		{"too short", Prefix + base64.StdEncoding.EncodeToString([]byte("short")), ErrMalformed},
		{"tampered ciphertext", tamper(t, valid, 20), ErrWrongKeyOrTampered},
		{"tampered nonce", tamper(t, valid, 0), ErrWrongKeyOrTampered},
		{"tampered tag", tamper(t, valid, -1), ErrWrongKeyOrTampered},
		{"wrong key", otherKey, ErrWrongKeyOrTampered},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.Decrypt(tt.value)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if got != "" {
				t.Fatalf("Decrypt returned %q alongside an error", got)
			}
			if strings.Contains(err.Error(), plaintext) {
				t.Fatalf("error leaks the plaintext: %v", err)
			}
		})
	}
}

// tamper flips one bit of the sealed bytes at index i (negative counts from
// the end).
func tamper(t *testing.T, value string, i int) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, Prefix))
	if err != nil {
		t.Fatal(err)
	}
	if i < 0 {
		i += len(raw)
	}
	raw[i] ^= 0x01
	return Prefix + base64.StdEncoding.EncodeToString(raw)
}

func TestLoadOrCreateKeyCreatesAndReuses(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")

	first, err := LoadOrCreateKey(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != KeySize {
		t.Fatalf("key length = %d", len(first))
	}
	path := filepath.Join(dir, KeyFileName)
	onDisk, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(onDisk, first) {
		t.Fatalf("key file content differs from returned key (err %v)", err)
	}
	assertOwnerOnly(t, path)
	assertNoTempFiles(t, dir)

	second, err := LoadOrCreateKey(dir, "")
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("second load returned another key (err %v)", err)
	}
}

func assertOwnerOnly(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return // Unix permission bits are not meaningful on Windows.
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("mode = %o, want 600", mode)
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

func TestLoadOrCreateKeyRejectsWrongLengthFile(t *testing.T) {
	for _, n := range []int{0, 16, 33} {
		dir := t.TempDir()
		path := filepath.Join(dir, KeyFileName)
		content := bytes.Repeat([]byte{7}, n)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreateKey(dir, ""); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("%d-byte key file: err = %v, want ErrInvalidKey", n, err)
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(after, content) {
			t.Fatalf("%d-byte key file was modified", n)
		}
	}
}

func TestLoadOrCreateKeyEnvOverride(t *testing.T) {
	envKey := bytes.Repeat([]byte{9}, KeySize)
	tests := []struct {
		name    string
		env     string
		want    []byte
		wantErr error
	}{
		{"valid", base64.StdEncoding.EncodeToString(envKey), envKey, nil},
		{"surrounding whitespace", " " + base64.StdEncoding.EncodeToString(envKey) + "\n", envKey, nil},
		{"not base64", "not-base64!", nil, ErrInvalidKey},
		{"too short", base64.StdEncoding.EncodeToString(envKey[:16]), nil, ErrInvalidKey},
		{"too long", base64.StdEncoding.EncodeToString(append(envKey, 1)), nil, ErrInvalidKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			got, err := LoadOrCreateKey(dir, tt.env)
			if !errors.Is(err, tt.wantErr) || !bytes.Equal(got, tt.want) {
				t.Fatalf("LoadOrCreateKey = %x, %v; want %x, %v", got, err, tt.want, tt.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), strings.TrimSpace(tt.env)) {
				t.Fatalf("error leaks the env value: %v", err)
			}
			if _, statErr := os.Stat(filepath.Join(dir, KeyFileName)); !os.IsNotExist(statErr) {
				t.Fatalf("env override must not create a key file (stat err %v)", statErr)
			}
		})
	}
}

func TestLoadOrCreateKeyFileSystemErrors(t *testing.T) {
	t.Run("data dir is a file", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreateKey(filepath.Join(file, "data"), ""); err == nil {
			t.Fatal("want an error when the data directory cannot be created")
		}
	})
	t.Run("key path is a directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, KeyFileName), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreateKey(dir, ""); err == nil {
			t.Fatal("want an error when the key file cannot be read")
		}
	})
}
