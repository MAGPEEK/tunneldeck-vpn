package domain

import (
	"crypto/rand"
	"encoding/hex"
)

// idBytes is the size of a generated ID: 128 random bits.
const idBytes = 16

// NewID returns a random 128-bit identifier as 32 lowercase hex characters.
func NewID() string {
	b := make([]byte, idBytes)
	// crypto/rand.Read never returns an error; it crashes the program if
	// the system random source fails.
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
