package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"testing"

	"tunneldeck/internal/domain"
)

type fakeDriver struct{ protocol domain.Protocol }

func (f fakeDriver) Protocol() domain.Protocol                          { return f.protocol }
func (fakeDriver) Describe() FormSchema                                 { return FormSchema{} }
func (fakeDriver) Validate(domain.Profile) error                        { return nil }
func (fakeDriver) Start(context.Context, domain.Profile, Secrets) error { return nil }
func (fakeDriver) Stop(context.Context) error                           { return nil }
func (fakeDriver) Events() <-chan domain.Event                          { return nil }

func factoryFor(protocol domain.Protocol) Factory {
	return func() Driver { return fakeDriver{protocol: protocol} }
}

func TestRegistryRegisterAndLookup(t *testing.T) {
	r := NewRegistry()
	if err := r.Register("openvpn", factoryFor("openvpn")); err != nil {
		t.Fatalf("Register: %v", err)
	}
	factory, err := r.Lookup("openvpn")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got := factory().Protocol(); got != "openvpn" {
		t.Errorf("driver protocol = %q, want openvpn", got)
	}
}

func TestRegistryRegisterErrors(t *testing.T) {
	r := NewRegistry()
	if err := r.Register("openvpn", factoryFor("openvpn")); err != nil {
		t.Fatalf("Register: %v", err)
	}
	tests := []struct {
		name     string
		protocol domain.Protocol
		factory  Factory
		wantIs   error
	}{
		{name: "duplicate", protocol: "openvpn", factory: factoryFor("openvpn"), wantIs: domain.ErrConflict},
		{name: "empty protocol", protocol: "", factory: factoryFor("x")},
		{name: "nil factory", protocol: "wireguard", factory: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := r.Register(tt.protocol, tt.factory)
			if err == nil {
				t.Fatal("Register succeeded, want error")
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("error %v does not wrap %v", err, tt.wantIs)
			}
		})
	}
}

func TestRegistryLookupUnknown(t *testing.T) {
	_, err := NewRegistry().Lookup("ipsec")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Lookup error = %v, want ErrNotFound", err)
	}
}

func TestRegistryProtocolsSorted(t *testing.T) {
	r := NewRegistry()
	for _, p := range []domain.Protocol{"wireguard", "ipsec", "openvpn"} {
		if err := r.Register(p, factoryFor(p)); err != nil {
			t.Fatalf("Register %s: %v", p, err)
		}
	}
	want := []domain.Protocol{"ipsec", "openvpn", "wireguard"}
	if got := r.Protocols(); !slices.Equal(got, want) {
		t.Errorf("Protocols = %v, want %v", got, want)
	}
}

func TestRegistryConcurrentUse(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = r.Register(domain.Protocol(rune('a'+i)), factoryFor("x"))
		}()
		go func() {
			defer wg.Done()
			_ = r.Protocols()
			_, _ = r.Lookup("a")
		}()
	}
	wg.Wait()
	if got := len(r.Protocols()); got != 8 {
		t.Errorf("registered %d protocols, want 8", got)
	}
}

func TestFormSchemaJSON(t *testing.T) {
	schema := FormSchema{Sections: []Section{{
		Key:      "server",
		LabelKey: "openvpn.section.server",
		Fields: []Field{
			{Key: "port", Type: FieldNumber, LabelKey: "openvpn.port", Required: true, Default: 1194},
			{
				Key: "username", Type: FieldText, LabelKey: "openvpn.username",
				VisibleWhen: &Condition{Key: "authMode", Equals: []string{"password"}},
				Placeholder: "user",
			},
			{
				Key: "proto", Type: FieldSelect, LabelKey: "openvpn.proto",
				Options: []Option{{Value: "udp", LabelKey: "openvpn.proto.udp"}},
			},
			{Key: "clientKey", Type: FieldSecret, LabelKey: "openvpn.clientKey", Multiline: true},
		},
	}}}
	got, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"sections":[{"key":"server","labelKey":"openvpn.section.server","fields":[` +
		`{"key":"port","type":"number","labelKey":"openvpn.port","required":true,"default":1194},` +
		`{"key":"username","type":"text","labelKey":"openvpn.username","visibleWhen":{"key":"authMode","equals":["password"]},"placeholder":"user"},` +
		`{"key":"proto","type":"select","labelKey":"openvpn.proto","options":[{"value":"udp","labelKey":"openvpn.proto.udp"}]},` +
		`{"key":"clientKey","type":"secret","labelKey":"openvpn.clientKey","multiline":true}]}]}`
	if string(got) != want {
		t.Errorf("JSON =\n%s\nwant\n%s", got, want)
	}
}
