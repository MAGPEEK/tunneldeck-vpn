package openvpn

import (
	"slices"
	"strings"

	"tunneldeck/internal/domain"
)

// Starts of the log lines in which openvpn names what it negotiated, e.g.
// "Data Channel: cipher 'CHACHA20-POLY1305', peer-id: 0" and
// "Control Channel: TLSv1.3, cipher TLSv1.3 TLS_CHACHA20_POLY1305_SHA256,
// peer certificate: 384 bits ECsecp384r1, signature: ecdsa-with-SHA384".
const (
	dataChannelPrefix    = "Data Channel: cipher '"
	controlChannelPrefix = "Control Channel: "
	controlCipherPrefix  = "cipher "
)

// nullCipherNames are the names openvpn logs for an unencrypted data
// channel.
var nullCipherNames = []string{"[null-cipher]", cipherNone}

// channelEvent reads the negotiated data-channel cipher ("none" when
// unencrypted) or the control channel's TLS version and cipher suite from
// a log line; ok is false for every other line.
func channelEvent(text string) (domain.ChannelEvent, bool) {
	if cipher, ok := dataCipher(text); ok {
		return domain.ChannelEvent{DataCipher: cipher}, true
	}
	if control, ok := controlChannel(text); ok {
		return domain.ChannelEvent{ControlChannel: control}, true
	}
	return domain.ChannelEvent{}, false
}

func dataCipher(text string) (string, bool) {
	rest, ok := strings.CutPrefix(text, dataChannelPrefix)
	if !ok {
		return "", false
	}
	cipher, _, closed := strings.Cut(rest, "'")
	switch {
	case !closed || cipher == "":
		return "", false
	case slices.ContainsFunc(nullCipherNames, func(name string) bool { return strings.EqualFold(name, cipher) }):
		return cipherNone, true
	}
	return cipher, true
}

// controlChannel returns "<TLS version> <cipher suite>", the suite being
// the last word of the cipher field, which older OpenSSL versions prefix
// with a protocol family such as "TLSv1/SSLv3".
func controlChannel(text string) (string, bool) {
	rest, ok := strings.CutPrefix(text, controlChannelPrefix)
	if !ok {
		return "", false
	}
	version, cipherField, found := strings.Cut(rest, ", ")
	suite, isCipher := strings.CutPrefix(cipherField, controlCipherPrefix)
	suite, _, _ = strings.Cut(suite, ",")
	words := strings.Fields(suite)
	version = strings.TrimSpace(version)
	if !found || !isCipher || version == "" || len(words) == 0 {
		return "", false
	}
	return version + " " + words[len(words)-1], true
}
