package wireguard

import (
	"encoding/hex"
	"testing"
)

// RFC 7748 §6.1: Alice's private key and her public key.
const (
	rfcPrivateHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	rfcPublicHex  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
)

func keyFromHex(t *testing.T, text string) Key {
	t.Helper()
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != keyLength {
		t.Fatalf("bad test key %q", text)
	}
	return Key(raw)
}

func TestParseKey(t *testing.T) {
	valid := keyFromHex(t, rfcPublicHex).Base64()
	tests := []struct {
		name string
		text string
		ok   bool
	}{
		{"wg form", valid, true},
		{"empty", "", false},
		{"not base64", "not a key!", false},
		{"too short", valid[:40], false},
		{"too long", valid[:43] + "AAAA", false},
		{"surrounding spaces", " " + valid, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := ParseKey(tt.text)
			if (err == nil) != tt.ok {
				t.Fatalf("ParseKey(%q) error = %v, want ok %v", tt.text, err, tt.ok)
			}
			if tt.ok && k.Base64() != tt.text {
				t.Errorf("round trip = %q", k.Base64())
			}
		})
	}
}

func TestPublicKeyMatchesRFC7748(t *testing.T) {
	private := keyFromHex(t, rfcPrivateHex)
	public, err := PublicKeyOf(private.Base64())
	if err != nil {
		t.Fatal(err)
	}
	if want := keyFromHex(t, rfcPublicHex).Base64(); public != want {
		t.Errorf("public key = %s, want %s", public, want)
	}
	if _, err := PublicKeyOf("short"); err == nil {
		t.Error("PublicKeyOf accepted an invalid key")
	}
}

func TestGenerateKeyPair(t *testing.T) {
	seen := map[string]bool{}
	for range 8 {
		privateText, publicText, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		private, err := ParseKey(privateText)
		if err != nil {
			t.Fatalf("private key %v", err)
		}
		if private[0]&7 != 0 || private[31]&128 != 0 || private[31]&64 == 0 {
			t.Errorf("private key is not clamped: %x", private)
		}
		if derived, err := PublicKeyOf(privateText); err != nil || derived != publicText {
			t.Errorf("public key = %s, derived %s (%v)", publicText, derived, err)
		}
		if seen[privateText] {
			t.Error("the same private key was generated twice")
		}
		seen[privateText] = true
	}
}
