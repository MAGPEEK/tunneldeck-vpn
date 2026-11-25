package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// HashParams are the argon2id cost parameters. Every hash stores the
// parameters it was made with, so changing the defaults never invalidates
// existing hashes.
type HashParams struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultHashParams is the second recommended option of RFC 9106 §4:
// 64 MiB of memory, 3 passes, 4 lanes, 128-bit salt, 256-bit tag.
var DefaultHashParams = HashParams{
	MemoryKiB:   64 * 1024,
	Iterations:  3,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32,
}

// Bounds for parameters, both for new hashes and for stored ones, so a
// tampered settings file cannot make a login allocate unbounded memory.
const (
	maxMemoryKiB  = 1024 * 1024
	maxIterations = 64
	minSaltLength = 8
	maxSaltLength = 64
	minKeyLength  = 16
	maxKeyLength  = 64
)

const (
	hashAlgorithm = "argon2id"
	// maxParallelHashes bounds concurrent key derivations so parallel login
	// attempts cannot exhaust memory.
	maxParallelHashes = 2
)

// errMalformedHash reports a stored hash that cannot be parsed. It never
// carries the hash itself.
var errMalformedHash = errors.New("malformed password hash")

var hashEncoding = base64.RawStdEncoding

// passwordHash is a parsed argon2id hash.
type passwordHash struct {
	params HashParams
	salt   []byte
	key    []byte
}

// String encodes h in PHC string format:
// $argon2id$v=19$m=<KiB>,t=<iterations>,p=<lanes>$<salt>$<key>.
func (h passwordHash) String() string {
	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		hashAlgorithm, argon2.Version,
		h.params.MemoryKiB, h.params.Iterations, h.params.Parallelism,
		hashEncoding.EncodeToString(h.salt), hashEncoding.EncodeToString(h.key))
}

// parsePasswordHash decodes a PHC string produced by passwordHash.String.
func parsePasswordHash(encoded string) (passwordHash, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != hashAlgorithm {
		return passwordHash{}, errMalformedHash
	}
	if parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return passwordHash{}, fmt.Errorf("unsupported argon2 version: %w", errMalformedHash)
	}
	params, err := parseCostParams(parts[3])
	if err != nil {
		return passwordHash{}, err
	}
	salt, saltErr := hashEncoding.DecodeString(parts[4])
	key, keyErr := hashEncoding.DecodeString(parts[5])
	if saltErr != nil || keyErr != nil {
		return passwordHash{}, fmt.Errorf("invalid base64: %w", errMalformedHash)
	}
	params.SaltLength = uint32(len(salt))
	params.KeyLength = uint32(len(key))
	if err := params.validate(); err != nil {
		return passwordHash{}, err
	}
	return passwordHash{params: params, salt: salt, key: key}, nil
}

// parseCostParams parses "m=<KiB>,t=<iterations>,p=<lanes>".
func parseCostParams(field string) (HashParams, error) {
	values := strings.Split(field, ",")
	if len(values) != 3 {
		return HashParams{}, fmt.Errorf("invalid parameters: %w", errMalformedHash)
	}
	memory, errM := parseCostParam(values[0], "m", 32)
	iterations, errT := parseCostParam(values[1], "t", 32)
	parallelism, errP := parseCostParam(values[2], "p", 8)
	if err := errors.Join(errM, errT, errP); err != nil {
		return HashParams{}, err
	}
	return HashParams{
		MemoryKiB:   uint32(memory),
		Iterations:  uint32(iterations),
		Parallelism: uint8(parallelism),
	}, nil
}

func parseCostParam(value, name string, bitSize int) (uint64, error) {
	digits, ok := strings.CutPrefix(value, name+"=")
	if !ok {
		return 0, fmt.Errorf("missing parameter %s: %w", name, errMalformedHash)
	}
	n, err := strconv.ParseUint(digits, 10, bitSize)
	if err != nil {
		return 0, fmt.Errorf("invalid parameter %s: %w", name, errMalformedHash)
	}
	return n, nil
}

// validate checks that p is within the accepted bounds.
func (p HashParams) validate() error {
	switch {
	case p.Parallelism < 1:
		return fmt.Errorf("parallelism must be at least 1: %w", errMalformedHash)
	case p.MemoryKiB < 8*uint32(p.Parallelism) || p.MemoryKiB > maxMemoryKiB:
		return fmt.Errorf("memory out of range: %w", errMalformedHash)
	case p.Iterations < 1 || p.Iterations > maxIterations:
		return fmt.Errorf("iterations out of range: %w", errMalformedHash)
	case p.SaltLength < minSaltLength || p.SaltLength > maxSaltLength:
		return fmt.Errorf("salt length out of range: %w", errMalformedHash)
	case p.KeyLength < minKeyLength || p.KeyLength > maxKeyLength:
		return fmt.Errorf("key length out of range: %w", errMalformedHash)
	}
	return nil
}

// keyDeriver computes an argon2id key; argon2.IDKey in production.
type keyDeriver func(password, salt []byte, iterations, memoryKiB uint32, parallelism uint8, keyLength uint32) []byte

// passwordHasher hashes and checks passwords. It limits how many key
// derivations run at once, because each one allocates MemoryKiB.
type passwordHasher struct {
	params HashParams
	derive keyDeriver
	slots  chan struct{}
}

func newPasswordHasher() *passwordHasher {
	return &passwordHasher{
		params: DefaultHashParams,
		derive: argon2.IDKey,
		slots:  make(chan struct{}, maxParallelHashes),
	}
}

// hash returns the PHC string of password with a fresh random salt.
func (h *passwordHasher) hash(password string) (string, error) {
	if err := h.params.validate(); err != nil {
		return "", fmt.Errorf("hash parameters: %w", err)
	}
	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	stored := passwordHash{params: h.params, salt: salt}
	stored.key = h.deriveKey(stored, password)
	return stored.String(), nil
}

// matches reports whether password produces stored's key, using stored's
// parameters and a constant-time comparison.
func (h *passwordHasher) matches(stored passwordHash, password string) bool {
	key := h.deriveKey(stored, password)
	return subtle.ConstantTimeCompare(key, stored.key) == 1
}

// dummyHash has the cost of a real hash made with the current parameters.
// Checking a password against it costs the same as a real check.
func (h *passwordHasher) dummyHash() passwordHash {
	return passwordHash{
		params: h.params,
		salt:   make([]byte, h.params.SaltLength),
		key:    make([]byte, h.params.KeyLength),
	}
}

func (h *passwordHasher) deriveKey(stored passwordHash, password string) []byte {
	h.slots <- struct{}{}
	defer func() { <-h.slots }()
	p := stored.params
	return h.derive([]byte(password), stored.salt, p.Iterations, p.MemoryKiB, p.Parallelism, p.KeyLength)
}
