package domain

// Protocol names a VPN method. Each vpn.Driver serves exactly one protocol.
type Protocol string

// ProtocolOpenVPN is the protocol served by the OpenVPN driver.
const ProtocolOpenVPN Protocol = "openvpn"

// ConnectionState is a state of the tunnel (SPEC §4.2).
type ConnectionState string

// Connection states.
const (
	StateDisconnected  ConnectionState = "disconnected"
	StateConnecting    ConnectionState = "connecting"
	StateConnected     ConnectionState = "connected"
	StateReconnecting  ConnectionState = "reconnecting"
	StateDisconnecting ConnectionState = "disconnecting"
	StateError         ConnectionState = "error"
)

// Language is a UI language.
type Language string

// Supported UI languages.
const (
	LanguageGerman  Language = "de"
	LanguageEnglish Language = "en"
)

// DefaultLanguage is used until an admin chooses another default.
const DefaultLanguage = LanguageEnglish

// Valid reports whether l is a supported language.
func (l Language) Valid() bool {
	return l == LanguageGerman || l == LanguageEnglish
}

// AdminAccount is the single admin. PasswordHash is produced and checked by
// the auth package; domain only carries it.
type AdminAccount struct {
	Username     string `json:"username"`
	PasswordHash string `json:"passwordHash"`
}

// DesiredConnection is the persisted wish of the user, used to reconnect
// after a container restart.
type DesiredConnection struct {
	ActiveProfileID string `json:"activeProfileId"`
	WantConnected   bool   `json:"wantConnected"`
}

// Validate checks that a wanted connection names a profile.
func (d DesiredConnection) Validate() error {
	if d.WantConnected && d.ActiveProfileID == "" {
		return NewValidationError("activeProfileId", "is required when wantConnected is true")
	}
	return nil
}
