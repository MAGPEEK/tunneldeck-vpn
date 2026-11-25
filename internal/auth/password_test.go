package auth

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

func newCheapHasher() *passwordHasher {
	h := newPasswordHasher()
	h.params = cheapParams
	return h
}

func TestDefaultHashParamsFollowRFC9106(t *testing.T) {
	want := HashParams{MemoryKiB: 65536, Iterations: 3, Parallelism: 4, SaltLength: 16, KeyLength: 32}
	if DefaultHashParams != want {
		t.Fatalf("DefaultHashParams = %+v, want %+v", DefaultHashParams, want)
	}
	if err := DefaultHashParams.validate(); err != nil {
		t.Fatalf("DefaultHashParams invalid: %v", err)
	}
}

func TestHashIsPHCStringWithParameters(t *testing.T) {
	encoded, err := newCheapHasher().hash(testPassword)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	format := regexp.MustCompile(`^\$argon2id\$v=19\$m=64,t=1,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`)
	if !format.MatchString(encoded) {
		t.Fatalf("hash %q does not match PHC format", encoded)
	}
	if strings.Contains(encoded, testPassword) {
		t.Fatal("hash contains the password")
	}
}

func TestHashUsesFreshSalt(t *testing.T) {
	h := newCheapHasher()
	first, err1 := h.hash(testPassword)
	second, err2 := h.hash(testPassword)
	if err := errors.Join(err1, err2); err != nil {
		t.Fatalf("hash: %v", err)
	}
	if first == second {
		t.Fatal("two hashes of the same password are equal")
	}
}

func TestHashRejectsInvalidParams(t *testing.T) {
	h := newCheapHasher()
	h.params.Iterations = 0
	if _, err := h.hash(testPassword); !errors.Is(err, errMalformedHash) {
		t.Fatalf("hash with invalid params: err = %v", err)
	}
}

func TestMatchesUsesStoredParameters(t *testing.T) {
	writer := newCheapHasher()
	writer.params = HashParams{MemoryKiB: 128, Iterations: 2, Parallelism: 2, SaltLength: 12, KeyLength: 24}
	encoded, err := writer.hash(testPassword)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	stored, err := parsePasswordHash(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if stored.params != writer.params {
		t.Fatalf("parsed params = %+v, want %+v", stored.params, writer.params)
	}
	if stored.String() != encoded {
		t.Fatalf("String() = %q, want %q", stored.String(), encoded)
	}
	reader := newCheapHasher()
	tests := []struct {
		name     string
		password string
		want     bool
	}{
		{"correct password", testPassword, true},
		{"wrong password", testPassword + "x", false},
		{"empty password", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reader.matches(stored, tt.password); got != tt.want {
				t.Fatalf("matches = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePasswordHashRejectsMalformed(t *testing.T) {
	salt := "AAAAAAAAAAAAAAAAAAAAAA"
	key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	valid := "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$" + key
	if _, err := parsePasswordHash(valid); err != nil {
		t.Fatalf("valid hash rejected: %v", err)
	}
	tests := []struct {
		name    string
		encoded string
	}{
		{"empty", ""},
		{"plain text", "secret password"},
		{"argon2i", "$argon2i$v=19$m=64,t=1,p=1$" + salt + "$" + key},
		{"bcrypt", "$2a$10$abcdefghijklmnopqrstuu"},
		{"missing part", "$argon2id$v=19$m=64,t=1,p=1$" + salt},
		{"extra part", valid + "$x"},
		{"no leading dollar", "argon2id$v=19$m=64,t=1,p=1$" + salt + "$" + key + "$"},
		{"old version", "$argon2id$v=16$m=64,t=1,p=1$" + salt + "$" + key},
		{"two params", "$argon2id$v=19$m=64,t=1$" + salt + "$" + key},
		{"params out of order", "$argon2id$v=19$t=1,m=64,p=1$" + salt + "$" + key},
		{"non-numeric param", "$argon2id$v=19$m=abc,t=1,p=1$" + salt + "$" + key},
		{"negative param", "$argon2id$v=19$m=64,t=-1,p=1$" + salt + "$" + key},
		{"parallelism overflow", "$argon2id$v=19$m=64,t=1,p=256$" + salt + "$" + key},
		{"zero parallelism", "$argon2id$v=19$m=64,t=1,p=0$" + salt + "$" + key},
		{"zero iterations", "$argon2id$v=19$m=64,t=0,p=1$" + salt + "$" + key},
		{"too many iterations", "$argon2id$v=19$m=64,t=65,p=1$" + salt + "$" + key},
		{"memory below 8 per lane", "$argon2id$v=19$m=15,t=1,p=2$" + salt + "$" + key},
		{"memory above bound", "$argon2id$v=19$m=1048577,t=1,p=1$" + salt + "$" + key},
		{"salt not base64", "$argon2id$v=19$m=64,t=1,p=1$!!!!$" + key},
		{"key not base64", "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$!!!!"},
		{"salt too short", "$argon2id$v=19$m=64,t=1,p=1$AAAA$" + key},
		{"key too short", "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$AAAA"},
		{"key too long", "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$" + strings.Repeat("A", 100)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePasswordHash(tt.encoded)
			if !errors.Is(err, errMalformedHash) {
				t.Fatalf("parsePasswordHash: err = %v, want errMalformedHash", err)
			}
			if tt.encoded != "" && strings.Contains(err.Error(), tt.encoded) {
				t.Fatal("error message contains the hash")
			}
		})
	}
}

func TestDummyHashHasCurrentCost(t *testing.T) {
	h := newCheapHasher()
	dummy := h.dummyHash()
	if dummy.params != cheapParams {
		t.Fatalf("dummy params = %+v, want %+v", dummy.params, cheapParams)
	}
	if h.matches(dummy, testPassword) {
		t.Fatal("dummy hash matched a password")
	}
}
