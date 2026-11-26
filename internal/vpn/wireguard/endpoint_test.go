package wireguard

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		text string
		want string // "" = invalid
	}{
		{"vpn.example.com:51820", "vpn.example.com:51820"},
		{"vpn.example.com", "vpn.example.com:51820"},
		{"vpn.example.com.:443", "vpn.example.com.:443"},
		{"198.51.100.23:1194", "198.51.100.23:1194"},
		{"198.51.100.23", "198.51.100.23:51820"},
		{"[2001:db8::1]:51820", "[2001:db8::1]:51820"},
		{"2001:db8::1", "[2001:db8::1]:51820"},
		{"[::ffff:198.51.100.23]:51820", "198.51.100.23:51820"},
		{"vpn.example.com:0", ""},
		{"vpn.example.com:65536", ""},
		{"vpn.example.com:http", ""},
		{"vpn_example.com:51820", ""},
		{"[vpn.example.com]", ""},
		{"fe80::1%eth0", ""},
		{":51820", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			e, ok := parseEndpoint(tt.text)
			if ok != (tt.want != "") {
				t.Fatalf("parseEndpoint(%q) ok = %v", tt.text, ok)
			}
			if ok && e.String() != tt.want {
				t.Errorf("parseEndpoint(%q) = %s, want %s", tt.text, e, tt.want)
			}
		})
	}
}

// fakeResolver answers from a map and counts the lookups. With hold set,
// a lookup first signals entered and then waits until hold is closed or
// its context ends, like a name server that does not answer.
type fakeResolver struct {
	answers map[string][]netip.Addr
	err     error
	lookups int
	hold    chan struct{}
	entered chan struct{}
}

func (r *fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	r.lookups++
	if r.hold != nil {
		r.entered <- struct{}{}
		select {
		case <-r.hold:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if network != "ip" {
		return nil, errors.New("unexpected network " + network)
	}
	if r.err != nil {
		return nil, r.err
	}
	return r.answers[host], nil
}

func TestResolve(t *testing.T) {
	addrs := func(texts ...string) []netip.Addr {
		var list []netip.Addr
		for _, text := range texts {
			list = append(list, netip.MustParseAddr(text))
		}
		return list
	}
	resolver := &fakeResolver{answers: map[string][]netip.Addr{
		"dual.example":   addrs("2001:db8::7", "::ffff:198.51.100.7", "198.51.100.8"),
		"v6only.example": addrs("2001:db8::9"),
	}}
	tests := []struct {
		endpoint string
		want     string // "" = error
	}{
		{"198.51.100.1:51820", "198.51.100.1:51820"},
		{"dual.example:51821", "198.51.100.7:51821"},
		{"v6only.example", "[2001:db8::9]:51820"},
		{"unknown.example", ""},
	}
	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			e, _ := parseEndpoint(tt.endpoint)
			got, err := resolve(context.Background(), resolver, e)
			if (err == nil) != (tt.want != "") {
				t.Fatalf("resolve = %v, %v", got, err)
			}
			if err == nil && got.String() != tt.want {
				t.Errorf("resolve = %s, want %s", got, tt.want)
			}
		})
	}
	failing := &fakeResolver{err: errors.New("no such host")}
	e, _ := parseEndpoint("vpn.example.com")
	if _, err := resolve(context.Background(), failing, e); err == nil || failing.lookups != 1 {
		t.Errorf("resolve with a failing resolver = %v after %d lookups", err, failing.lookups)
	}
}
