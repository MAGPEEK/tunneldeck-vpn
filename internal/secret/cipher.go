package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// KeySize is the length of an AES-256 key in bytes.
const KeySize = 32

// Prefix marks a value encrypted by Cipher (format version 1).
const Prefix = "enc:v1:"

// Errors returned by this package. They never contain key material or
// plaintext.
var (
	// ErrInvalidKey reports a key that is not KeySize bytes long or cannot
	// be decoded.
	ErrInvalidKey = errors.New("secret: invalid key")
	// ErrMalformed reports a value that is not in the enc:v1 format.
	ErrMalformed = errors.New("secret: malformed encrypted value")
	// ErrWrongKeyOrTampered reports a value that fails authentication:
	// it was encrypted with another key or has been modified.
	ErrWrongKeyOrTampered = errors.New("secret: wrong key or tampered value")
)

// Cipher encrypts secret fields with AES-256-GCM and a random 12-byte nonce.
// Encrypted values have the form "enc:v1:" + base64(nonce || ciphertext).
// It is safe for concurrent use.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher returns a Cipher for a KeySize-byte key.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidKey, len(key), KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secret: create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("secret: create GCM: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt returns plaintext in the enc:v1 format. Each call uses a fresh
// random nonce, so equal plaintexts give different results. The error is
// always nil for this implementation; it is part of the signature so callers
// can depend on an interface that other implementations may fail.
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	sealed := c.aead.Seal(nil, nil, []byte(plaintext), nil)
	return Prefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt reverses Encrypt. A value without the enc:v1 prefix is rejected
// with ErrMalformed; there is no plaintext passthrough. A value that fails
// authentication gives ErrWrongKeyOrTampered.
func (c *Cipher) Decrypt(value string) (string, error) {
	encoded, ok := strings.CutPrefix(value, Prefix)
	if !ok {
		return "", fmt.Errorf("%w: missing %q prefix", ErrMalformed, Prefix)
	}
	sealed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("%w: invalid base64", ErrMalformed)
	}
	if len(sealed) < c.aead.Overhead() {
		return "", fmt.Errorf("%w: too short", ErrMalformed)
	}
	plaintext, err := c.aead.Open(nil, nil, sealed, nil)
	if err != nil {
		return "", ErrWrongKeyOrTampered
	}
	return string(plaintext), nil
}
