package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/remoteaccess"
)

type remoteAccessRequest struct {
	Enabled           bool                     `json:"enabled"`
	Port              int                      `json:"port"`
	CertificateSource domain.CertificateSource `json:"certificateSource"`
}

type certificateUpload struct {
	CertificatePEM string `json:"certificatePem"`
	KeyPEM         string `json:"keyPem"`
}

// certificateResponse describes a certificate; it never carries the key.
type certificateResponse struct {
	Subject           string    `json:"subject"`
	NotBefore         time.Time `json:"notBefore"`
	NotAfter          time.Time `json:"notAfter"`
	FingerprintSHA256 string    `json:"fingerprintSha256"`
	SelfSigned        bool      `json:"selfSigned"`
}

type remoteAccessResponse struct {
	Enabled           bool                     `json:"enabled"`
	Port              int                      `json:"port"`
	CertificateSource domain.CertificateSource `json:"certificateSource"`
	// Certificate is the certificate of the chosen source, null while none
	// exists (a self-signed one is generated on first enable).
	Certificate *certificateResponse `json:"certificate"`
	Listening   bool                 `json:"listening"`
	LastError   string               `json:"lastError,omitempty"`
}

func (s *Server) getRemoteAccess(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.remoteAccessState())
}

// putRemoteAccess validates, stores and applies the setting. When applying
// fails, the previous setting is stored and applied again.
func (s *Server) putRemoteAccess(w http.ResponseWriter, r *http.Request) {
	var body remoteAccessRequest
	if err := s.readJSON(w, r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	next := domain.RemoteAccess(body)
	s.portsMu.Lock()
	defer s.portsMu.Unlock()
	if err := s.validateRemoteAccess(next); err != nil {
		writeError(w, r, err)
		return
	}
	previous := s.deps.RemoteAccess.RemoteAccess()
	if err := s.deps.RemoteAccess.SetRemoteAccess(next); err != nil {
		writeError(w, r, err)
		return
	}
	if err := s.deps.RemoteAccessListener.Apply(r.Context(), next); err != nil {
		s.rollbackRemoteAccess(r.Context(), previous, err)
		writeRemoteAccessFailed(w)
		return
	}
	writeJSON(w, http.StatusOK, s.remoteAccessState())
}

func (s *Server) rollbackRemoteAccess(ctx context.Context, previous domain.RemoteAccess, cause error) {
	slog.Error("apply remote access", "error", cause)
	if err := s.deps.RemoteAccess.SetRemoteAccess(previous); err != nil {
		slog.Error("roll back the remote-access setting", "error", err)
	}
	if err := s.deps.RemoteAccessListener.Apply(context.WithoutCancel(ctx), previous); err != nil {
		slog.Error("re-apply the previous remote-access setting", "error", err)
	}
}

// uploadCertificate validates and stores an uploaded certificate. It does
// not change the source; when the uploaded certificate is the one being
// served, the listener switches to the new one.
func (s *Server) uploadCertificate(w http.ResponseWriter, r *http.Request) {
	var body certificateUpload
	if err := s.readJSON(w, r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	pair, err := remoteaccess.ParseUpload(body.CertificatePEM, body.KeyPEM, s.now())
	if err != nil {
		writeError(w, r, err)
		return
	}
	s.portsMu.Lock()
	defer s.portsMu.Unlock()
	if err := s.deps.RemoteAccess.SetRemoteAccessKeyPair(domain.CertificateUploaded, pair); err != nil {
		writeError(w, r, err)
		return
	}
	current := s.deps.RemoteAccess.RemoteAccess()
	if current.Enabled && current.CertificateSource == domain.CertificateUploaded {
		if err := s.deps.RemoteAccessListener.Apply(r.Context(), current); err != nil {
			slog.Error("serve the uploaded certificate", "error", err)
			writeRemoteAccessFailed(w)
			return
		}
	}
	writeJSON(w, http.StatusOK, s.remoteAccessState())
}

func writeRemoteAccessFailed(w http.ResponseWriter) {
	writeProblem(w, newProblem(http.StatusInternalServerError, CodeRemoteAccessFailed,
		"Remote access could not be applied; the previous setting was kept."))
}

// validateRemoteAccess applies the domain rules, keeps the port off the UI
// port and the public ports of enabled inbound TCP firewall rules (SPEC §8.1) and requires an
// uploaded certificate for the uploaded source. The caller holds s.portsMu.
func (s *Server) validateRemoteAccess(settings domain.RemoteAccess) error {
	v := &domain.ValidationError{}
	var fields *domain.ValidationError
	if errors.As(settings.Validate(), &fields) {
		v.Merge("", fields)
	}
	if settings.Port == s.deps.System.UIPort {
		v.AddIssue("port", domain.Issue("remote_access_ui_port"), "must not be the web UI port")
	}
	if settings.Enabled && s.usedByFirewall(settings.Port) {
		v.AddIssue("port", domain.Issue("remote_access_port_in_firewall"), "is opened by an enabled firewall rule")
	}
	if settings.CertificateSource == domain.CertificateUploaded {
		if _, ok := s.deps.RemoteAccess.RemoteAccessCertificate(domain.CertificateUploaded); !ok {
			v.AddIssue("certificateSource", domain.Issue("remote_access_certificate_missing"), "upload a certificate first")
		}
	}
	return v.OrNil()
}

// usedByFirewall reports whether an enabled inbound TCP rule accepts port
// on the public address.
func (s *Server) usedByFirewall(port int) bool {
	return domain.CheckReservedPorts(s.deps.FirewallStore.Firewall().Rules, 0, port) != nil
}

func (s *Server) remoteAccessState() remoteAccessResponse {
	settings := s.deps.RemoteAccess.RemoteAccess()
	status := s.deps.RemoteAccessListener.Status()
	return remoteAccessResponse{
		Enabled:           settings.Enabled,
		Port:              settings.Port,
		CertificateSource: settings.CertificateSource,
		Certificate:       s.describeCertificate(settings.CertificateSource),
		Listening:         status.Listening,
		LastError:         status.LastError,
	}
}

func (s *Server) describeCertificate(source domain.CertificateSource) *certificateResponse {
	certificatePEM, ok := s.deps.RemoteAccess.RemoteAccessCertificate(source)
	if !ok {
		return nil
	}
	info, err := remoteaccess.Describe(certificatePEM)
	if err != nil {
		slog.Error("describe the remote-access certificate", "source", source, "error", err)
		return nil
	}
	return &certificateResponse{
		Subject:           info.Subject,
		NotBefore:         info.NotBefore,
		NotAfter:          info.NotAfter,
		FingerprintSHA256: info.FingerprintSHA256,
		SelfSigned:        info.SelfSigned,
	}
}
