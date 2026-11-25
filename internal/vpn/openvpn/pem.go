package openvpn

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
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

var (
	errNotCertificate = errors.New("must contain one or more PEM certificates (RFC 7468)")
	errNotPrivateKey  = errors.New("must contain exactly one PEM private key (RFC 7468)")
	errNotStaticKey   = errors.New("must be an OpenVPN static key (2048 bit, V1)")
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
