package domain

import (
	"strings"
	"testing"
)

func TestIsPublicAddress(t *testing.T) {
	tests := []struct {
		address string
		want    bool
	}{
		{"203.0.113.10", true},
		{"vpn.example.com", true},
		{"vpn.example.com.", true},
		{"my-router", true},
		{"a1.b2", true},
		{"", false},
		{"300.1.2.3", false},
		{"1.2.3", false},
		{"2001:db8::1", false},
		{"https://vpn.example.com", false},
		{"vpn.example.com:8443", false},
		{"-bad.example.com", false},
		{"bad-.example.com", false},
		{"two..dots", false},
		{"with space.example.com", false},
		{strings.Repeat("a", 64) + ".example.com", false},
		{strings.Repeat("abcdefghi.", 26) + "com", false},
	}
	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			if got := isPublicAddress(tt.address); got != tt.want {
				t.Errorf("isPublicAddress(%q) = %v, want %v", tt.address, got, tt.want)
			}
		})
	}
}
