package wireguard

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// keyLength is the size of a Curve25519 key in bytes.
const keyLength = 32

// Key is a WireGuard key: a Curve25519 private or public key, or a
// pre-shared key. It deliberately has no String method, so a private key
// cannot end up in a log line through fmt.
type Key [keyLength]byte

// errKeyInvalid is the error of ParseKey.
var errKeyInvalid = errors.New("must be a WireGuard key: 32 bytes in base64, as wg genkey prints it")

// ParseKey decodes a key in the base64 form wg and wg-quick files use.
func ParseKey(text string) (Key, error) {
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil || len(raw) != keyLength {
		return Key{}, errKeyInvalid
	}
	return Key(raw), nil
}

// Base64 returns the key in the form wg prints it.
func (k Key) Base64() string { return base64.StdEncoding.EncodeToString(k[:]) }

// hex returns the key in the lowercase hex form of the UAPI.
func (k Key) hex() string { return hex.EncodeToString(k[:]) }

// isZero reports whether every byte of k is zero; wireguard-go treats a zero
// private key as no key.
func (k Key) isZero() bool { return k == Key{} }

// PublicKey derives the public key of the private key k: X25519 of k with
// the base point, which clamps k as RFC 7748 requires.
func (k Key) PublicKey() (Key, error) {
	private, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		return Key{}, fmt.Errorf("derive the public key: %w", err)
	}
	return Key(private.PublicKey().Bytes()), nil
}

// clamp applies the Curve25519 clamping of RFC 7748 §5, as wg genkey does.
func (k *Key) clamp() {
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
}

// GenerateKeyPair returns a new private key and its public key in base64.
// The private key is clamped like the output of wg genkey.
func GenerateKeyPair() (privateKey, publicKey string, err error) {
	var private Key
	if _, err := rand.Read(private[:]); err != nil {
		return "", "", fmt.Errorf("generate a private key: %w", err)
	}
	private.clamp()
	public, err := private.PublicKey()
	if err != nil {
		return "", "", err
	}
	return private.Base64(), public.Base64(), nil
}

// PublicKeyOf returns the public key of a private key in base64.
func PublicKeyOf(privateKey string) (string, error) {
	private, err := ParseKey(privateKey)
	if err != nil {
		return "", err
	}
	public, err := private.PublicKey()
	if err != nil {
		return "", err
	}
	return public.Base64(), nil
}
