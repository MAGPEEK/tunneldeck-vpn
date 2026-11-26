package openvpn

import (
	"testing"

	"tunneldeck/internal/domain"
)

func TestChannelEvent(t *testing.T) {
	tests := []struct {
		text string
		want domain.ChannelEvent
		ok   bool
	}{
		{text: "Data Channel: cipher 'CHACHA20-POLY1305', peer-id: 0", want: domain.ChannelEvent{DataCipher: "CHACHA20-POLY1305"}, ok: true},
		{text: "Data Channel: cipher 'AES-256-GCM', peer-id: 3, compression: 'lzo'", want: domain.ChannelEvent{DataCipher: "AES-256-GCM"}, ok: true},
		{text: "Data Channel: cipher 'BF-CBC', auth 'SHA1', peer-id: 0", want: domain.ChannelEvent{DataCipher: "BF-CBC"}, ok: true},
		{text: "Data Channel: cipher '[null-cipher]', auth '[null-digest]', peer-id: 0", want: domain.ChannelEvent{DataCipher: "none"}, ok: true},
		{text: "Data Channel: cipher 'none', auth 'none', peer-id: 0", want: domain.ChannelEvent{DataCipher: "none"}, ok: true},
		{
			text: "Control Channel: TLSv1.3, cipher TLSv1.3 TLS_CHACHA20_POLY1305_SHA256, peer certificate: 384 bits ECsecp384r1, signature: ecdsa-with-SHA384",
			want: domain.ChannelEvent{ControlChannel: "TLSv1.3 TLS_CHACHA20_POLY1305_SHA256"}, ok: true,
		},
		{
			text: "Control Channel: TLSv1.2, cipher TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384, 2048 bit RSA",
			want: domain.ChannelEvent{ControlChannel: "TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384"}, ok: true,
		},
		{
			text: "Control Channel: TLSv1.2, cipher TLSv1/SSLv3 ECDHE-RSA-AES256-GCM-SHA384, 2048 bit RSA",
			want: domain.ChannelEvent{ControlChannel: "TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384"}, ok: true,
		},
		{text: "Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384", want: domain.ChannelEvent{ControlChannel: "TLSv1.3 TLS_AES_256_GCM_SHA384"}, ok: true},
		{text: "Data Channel: cipher 'CHACHA20-POLY1305, peer-id: 0"},
		{text: "Data Channel: cipher '', peer-id: 0"},
		{text: "Control Channel: TLSv1.3"},
		{text: "Control Channel: TLSv1.3, peer certificate: 384 bits"},
		{text: "Control Channel: , cipher TLSv1.3 TLS_AES_256_GCM_SHA384"},
		{text: "Outgoing Data Channel: Cipher 'CHACHA20-POLY1305' initialized with 256 bit key"},
		{text: "WARNING: cipher 'none' specified for --data-ciphers."},
		{text: "Initialization Sequence Completed"},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			got, ok := channelEvent(tt.text)
			if ok != tt.ok || got != tt.want {
				t.Errorf("channelEvent = %+v, %v; want %+v, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestIsCipherNoneWarning(t *testing.T) {
	tests := []struct {
		text string
		want bool
	}{
		{"WARNING: cipher 'none' specified for --data-ciphers. This allows negotiation of NO encryption", true},
		{"******* WARNING *******: '--cipher none' was specified. This means NO encryption will be performed", true},
		{"******* WARNING *******: '--auth none' was specified.", false},
		{"Data Channel: cipher 'CHACHA20-POLY1305', peer-id: 0", false},
	}
	for _, tt := range tests {
		if got := isCipherNoneWarning(tt.text); got != tt.want {
			t.Errorf("isCipherNoneWarning(%q) = %v, want %v", tt.text, got, tt.want)
		}
	}
}
