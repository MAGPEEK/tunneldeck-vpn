package openvpn

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
)

// PEM block types (RFC 7468) accepted for client private keys.
const (
	pemCertificate         = "CERTIFICATE"
	pemPrivateKey          = "PRIVATE KEY"
	pemEncryptedPrivateKey = "ENCRYPTED PRIVATE KEY"
	pemRSAPrivateKey       = "RSA PRIVATE KEY"
	pemECPrivateKey        = "EC PRIVATE KEY"
	pemECParameters        = "EC PARAMETERS"
)

// OpenVPN static keys (tls-auth, tls-crypt) are 2048 bits, written as hex
// between these markers.
const (
	staticKeyBegin   = "-----BEGIN OpenVPN Static key V1-----"
	staticKeyEnd     = "-----END OpenVPN Static key V1-----"
	staticKeyBytes   = 256
	staticKeyHexLine = 32
)

// A tls-crypt-v2 client key is the 2048-bit client key followed by the
// server-wrapped key (WKc) of at most 1024 bytes, written as base64 in
// lines of 64 characters between these markers ("openvpn --genkey
// tls-crypt-v2-client").
const (
	tlsCryptV2Begin      = "-----BEGIN OpenVPN tls-crypt-v2 client key-----"
	tlsCryptV2End        = "-----END OpenVPN tls-crypt-v2 client key-----"
	tlsCryptV2MaxWKc     = 1024
	tlsCryptV2Base64Line = 64
)

// A PKCS#12 bundle (RFC 7292) is stored and rendered as base64. Its size is
// bounded; real bundles of a certificate chain and a key are a few KiB.
const (
	maxPKCS12Bytes    = 64 << 10
	pkcs12Base64Line  = 64
	derSequence       = 0x30
	derLongFormFlag   = 0x80
	derMaxLengthBytes = 4
)

// pkcs12Version is the DER encoding of "version INTEGER {v3(3)}", the first
// field of the PFX sequence.
var pkcs12Version = []byte{0x02, 0x01, 0x03}

var (
	errNotCertificate = errors.New("must contain one or more PEM certificates (RFC 7468)")
	errNotPrivateKey  = errors.New("must contain exactly one PEM private key (RFC 7468)")
	errNotStaticKey   = errors.New("must be an OpenVPN static key (2048 bit, V1)")
	errNotPKCS12      = errors.New("must be a base64-encoded PKCS#12 file (.p12, .pfx) of at most 64 KiB")
	errNotTLSCryptV2  = errors.New("must be an OpenVPN tls-crypt-v2 client key")
)

// canonicalCertificates checks that text holds only PEM certificates that
// parse as X.509 and returns them re-encoded. Explanatory text around the
// blocks is allowed by RFC 7468 and dropped.
func canonicalCertificates(text string) (string, error) {
	blocks, err := decodePEM(text)
	if err != nil || len(blocks) == 0 {
		return "", errNotCertificate
	}
	var out bytes.Buffer
	for _, block := range blocks {
		if block.Type != pemCertificate || len(block.Headers) > 0 {
			return "", errNotCertificate
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return "", errNotCertificate
		}
		out.Write(pem.EncodeToMemory(block))
	}
	return out.String(), nil
}

// canonicalPrivateKey checks that text holds exactly one PEM private key and
// returns it re-encoded. Unencrypted keys must parse; encrypted keys are
// passed on, OpenVPN asks for the passphrase over management. An
// "EC PARAMETERS" block, as written by openssl ecparam, is dropped.
func canonicalPrivateKey(text string) (string, error) {
	blocks, err := decodePEM(text)
	if err != nil {
		return "", errNotPrivateKey
	}
	var key *pem.Block
	for _, block := range blocks {
		switch {
		case block.Type == pemECParameters:
		case key == nil && isValidPrivateKey(block):
			key = block
		default:
			return "", errNotPrivateKey
		}
	}
	if key == nil {
		return "", errNotPrivateKey
	}
	return string(pem.EncodeToMemory(key)), nil
}

func isValidPrivateKey(block *pem.Block) bool {
	encrypted := block.Headers["Proc-Type"] != ""
	var err error
	switch block.Type {
	case pemEncryptedPrivateKey:
		return len(block.Headers) == 0
	case pemPrivateKey:
		_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case pemRSAPrivateKey:
		if encrypted {
			return true
		}
		_, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case pemECPrivateKey:
		if encrypted {
			return true
		}
		_, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return false
	}
	return err == nil && len(block.Headers) == 0
}

// decodePEM returns every PEM block in text. A "-----BEGIN" that does not
// start a well-formed block is an error, so a damaged block is never
// skipped silently.
func decodePEM(text string) ([]*pem.Block, error) {
	var blocks []*pem.Block
	rest := []byte(text)
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		blocks = append(blocks, block)
		rest = remaining
	}
	if strings.Count(text, "-----BEGIN") != len(blocks) {
		return nil, errors.New("malformed PEM block")
	}
	return blocks, nil
}

// canonicalStaticKey checks that text holds exactly one OpenVPN static key
// and returns it in the layout of "openvpn --genkey": 16 lines of 32 hex
// digits between the markers. Text around the key, such as the comment
// header of --genkey, is dropped.
func canonicalStaticKey(text string) (string, error) {
	if strings.Count(text, staticKeyBegin) != 1 {
		return "", errNotStaticKey
	}
	_, afterBegin, _ := strings.Cut(text, staticKeyBegin)
	body, _, found := strings.Cut(afterBegin, staticKeyEnd)
	if !found {
		return "", errNotStaticKey
	}
	key, err := hex.DecodeString(strings.Join(strings.Fields(body), ""))
	if err != nil || len(key) != staticKeyBytes {
		return "", errNotStaticKey
	}
	encoded := hex.EncodeToString(key)
	var out strings.Builder
	out.WriteString(staticKeyBegin + "\n")
	for start := 0; start < len(encoded); start += staticKeyHexLine {
		out.WriteString(encoded[start:start+staticKeyHexLine] + "\n")
	}
	out.WriteString(staticKeyEnd + "\n")
	return out.String(), nil
}

// canonicalPKCS12 checks that text is base64 of a plausible PKCS#12 bundle
// and returns it re-encoded in lines of 64 characters, as inline <pkcs12>
// content. Whitespace, such as the line breaks of an .ovpn block, is
// ignored. The bundle itself is not parsed: it may be encrypted, and
// OpenVPN asks for its passphrase over management.
func canonicalPKCS12(text string) (string, error) {
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text), ""))
	if err != nil || len(der) > maxPKCS12Bytes || !looksLikePKCS12(der) {
		return "", errNotPKCS12
	}
	return base64Lines(der, pkcs12Base64Line), nil
}

// canonicalTLSCryptV2Key checks that text holds exactly one tls-crypt-v2
// client key and returns it re-encoded in lines of 64 characters between
// the markers. Text around the key is dropped.
func canonicalTLSCryptV2Key(text string) (string, error) {
	if strings.Count(text, tlsCryptV2Begin) != 1 {
		return "", errNotTLSCryptV2
	}
	_, afterBegin, _ := strings.Cut(text, tlsCryptV2Begin)
	body, _, found := strings.Cut(afterBegin, tlsCryptV2End)
	if !found {
		return "", errNotTLSCryptV2
	}
	key, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(body), ""))
	if err != nil || len(key) <= staticKeyBytes || len(key) > staticKeyBytes+tlsCryptV2MaxWKc {
		return "", errNotTLSCryptV2
	}
	return tlsCryptV2Begin + "\n" + base64Lines(key, tlsCryptV2Base64Line) + tlsCryptV2End + "\n", nil
}

// base64Lines returns data as base64 in lines of width characters, each
// ending in a newline.
func base64Lines(data []byte, width int) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	var out strings.Builder
	for start := 0; start < len(encoded); start += width {
		out.WriteString(encoded[start:min(start+width, len(encoded))] + "\n")
	}
	return out.String()
}

// looksLikePKCS12 checks the start of a PFX structure (RFC 7292 §4): a
// SEQUENCE whose definite length matches the data, or an indefinite
// length (BER), followed by version 3.
func looksLikePKCS12(der []byte) bool {
	if len(der) < 2 || der[0] != derSequence {
		return false
	}
	header, length := 2, int(der[1])
	switch {
	case der[1] == derLongFormFlag:
		length = len(der) - header
	case der[1] > derLongFormFlag:
		count := int(der[1] &^ derLongFormFlag)
		if count > derMaxLengthBytes || len(der) < header+count {
			return false
		}
		length = 0
		for _, b := range der[header : header+count] {
			length = length<<8 | int(b)
		}
		header += count
	}
	return header+length == len(der) && bytes.HasPrefix(der[header:], pkcs12Version)
}

// isEncryptedPrivateKey reports whether text holds a PEM private key that
// needs a passphrase: PKCS#8 "ENCRYPTED PRIVATE KEY" or a legacy key with
// "Proc-Type: 4,ENCRYPTED".
func isEncryptedPrivateKey(text string) bool {
	blocks, err := decodePEM(text)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(blocks, func(block *pem.Block) bool {
		return block.Type == pemEncryptedPrivateKey || strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED")
	})
}
