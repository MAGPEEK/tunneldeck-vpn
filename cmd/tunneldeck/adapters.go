package main

import (
	"errors"
	"fmt"
	"net/http"

	"tunneldeck/internal/api"
	"tunneldeck/internal/auth"
	"tunneldeck/internal/domain"
	"tunneldeck/internal/netguard"
	"tunneldeck/internal/vpn/openvpn"
)

// authAdapter translates the auth errors into the ones the API maps.
type authAdapter struct{ *auth.Service }

func (a authAdapter) Login(username, password, clientIP string) (string, error) {
	token, err := a.Service.Login(username, password, clientIP)
	var rateLimit *auth.RateLimitError
	switch {
	case errors.As(err, &rateLimit):
		return "", &api.RateLimitError{RetryAfter: rateLimit.RetryAfter}
	case errors.Is(err, auth.ErrInvalidCredentials):
		return "", api.ErrInvalidCredentials
	}
	return token, err
}

// sessionCookies sets the auth session cookie; secure is true only on an
// HTTPS listener.
type sessionCookies struct{ secure bool }

func (c sessionCookies) Set(w http.ResponseWriter, token string) {
	auth.SetSessionCookie(w, token, c.secure)
}

func (c sessionCookies) Clear(w http.ResponseWriter) { auth.ClearSessionCookie(w, c.secure) }

func (sessionCookies) Token(r *http.Request) string { return auth.TokenFromRequest(r) }

// profileImporter imports configuration files of the drivers that support
// it: OpenVPN .ovpn files.
type profileImporter struct{}

func (profileImporter) Import(protocol domain.Protocol, text string) (api.ImportDraft, error) {
	if protocol != domain.ProtocolOpenVPN {
		return api.ImportDraft{}, fmt.Errorf("import %q: %w", protocol, domain.ErrNotFound)
	}
	result, err := openvpn.ImportOVPN(text)
	if err != nil {
		return api.ImportDraft{}, err
	}
	warnings := make([]api.ImportWarning, len(result.Warnings))
	for i, w := range result.Warnings {
		warnings[i] = api.ImportWarning{
			Code: w.Code, Severity: string(w.Severity), Directive: w.Directive, Line: w.Line, Message: w.Message,
		}
	}
	return api.ImportDraft{Settings: result.Settings, Secrets: result.Secrets, Warnings: warnings}, nil
}

func toCheckResults(results []netguard.CheckResult) []api.CheckResult {
	checks := make([]api.CheckResult, len(results))
	for i, r := range results {
		checks[i] = api.CheckResult{ID: r.ID, OK: r.OK, Detail: r.Detail, Hint: r.Hint}
	}
	return checks
}
