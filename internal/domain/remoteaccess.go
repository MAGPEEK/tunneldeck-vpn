package domain

// CertificateSource names where the certificate of the HTTPS listener comes
// from (SPEC §8.1).
type CertificateSource string

// Certificate sources.
const (
	CertificateSelfSigned CertificateSource = "selfSigned"
	CertificateUploaded   CertificateSource = "uploaded"
)

// Valid reports whether c is a known certificate source.
func (c CertificateSource) Valid() bool {
	return c == CertificateSelfSigned || c == CertificateUploaded
}

// DefaultRemoteAccessPort is the HTTPS port until the admin picks another.
const DefaultRemoteAccessPort = 8443

// RemoteAccess is the setting of the HTTPS listener that makes the UI
// reachable over the tunnel (SPEC §8.1).
type RemoteAccess struct {
	Enabled           bool              `json:"enabled"`
	Port              int               `json:"port"`
	CertificateSource CertificateSource `json:"certificateSource"`
}

// DefaultRemoteAccess is off, on port 8443, with a self-signed certificate.
func DefaultRemoteAccess() RemoteAccess {
	return RemoteAccess{Port: DefaultRemoteAccessPort, CertificateSource: CertificateSelfSigned}
}

// Validate checks port and certificate source.
func (r RemoteAccess) Validate() error {
	v := &ValidationError{}
	if r.Port < MinPort || r.Port > MaxPort {
		v.AddIssue("port", Issue("port_invalid"), "must be between 1 and 65535")
	}
	if !r.CertificateSource.Valid() {
		v.AddIssue("certificateSource", Issue("one_of", "values", "selfSigned, uploaded"), "must be selfSigned or uploaded")
	}
	return v.OrNil()
}

// KeyPair is a PEM certificate chain (leaf first) with its PEM private key.
// KeyPEM is a secret: it is stored encrypted and never leaves the server.
type KeyPair struct {
	CertificatePEM string
	KeyPEM         string
}
