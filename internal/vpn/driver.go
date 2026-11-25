package vpn

import (
	"context"

	"tunneldeck/internal/domain"
)

// Secrets holds the secret values of a profile keyed by the field names the
// driver defines, with the same shape as domain.Profile.Secrets.
type Secrets map[string]string

// Driver runs tunnels of one protocol. The ConnectionManager owns at most
// one active driver instance at a time and creates a new instance for every
// attempt. Drivers report outcomes as events and never retry on their own.
type Driver interface {
	// Protocol names the protocol the driver serves, for example "openvpn".
	Protocol() domain.Protocol
	// Describe returns the fields of the profile form.
	Describe() FormSchema
	// Validate checks the protocol-specific settings and secrets of p.
	Validate(p domain.Profile) error
	// Start brings the tunnel for p up with the secrets s. It returns once
	// the attempt is under way, without waiting for its events to be read;
	// ctx bounds only the start itself.
	Start(ctx context.Context, p domain.Profile, s Secrets) error
	// Stop takes the tunnel down and returns when it is down.
	Stop(ctx context.Context) error
	// Events streams state, traffic and log events. A tunnel that ends
	// without Stop reports a last state event "disconnected" or "error"
	// (with a domain.ErrorCode), or closes the channel.
	Events() <-chan domain.Event
}
