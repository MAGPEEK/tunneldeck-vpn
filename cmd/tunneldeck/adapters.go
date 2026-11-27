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
	"tunneldeck/internal/vpn/wireguard"
)

// authAdapter translates the auth errors into the ones the API maps.
type authAdapter struct{ *auth.Service }

func (a authAdapter) Login(username, password string, client api.LoginClient, remember bool) (string, error) {
	listener := auth.ListenerLAN
	if client.Remote {
		listener = auth.ListenerRemote
	}
	token, err := a.Service.Login(username, password, client.IP, listener, remember)
	var rateLimit *auth.RateLimitError
	var credentials *auth.CredentialsError
	switch {
	case errors.As(err, &rateLimit):
		return "", &api.RateLimitError{RetryAfter: rateLimit.RetryAfter, Remote: rateLimit.Remote}
	case errors.As(err, &credentials):
		return "", &api.InvalidCredentialsError{RetryAfter: credentials.RetryAfter}
	}
	return token, err
}

// sessionCookies sets the auth session cookie; the API passes secure on the
// HTTPS listener.
type sessionCookies struct{}

func (sessionCookies) Set(w http.ResponseWriter, token string, secure, remember bool) {
	auth.SetSessionCookie(w, token, secure, remember)
}

func (sessionCookies) Clear(w http.ResponseWriter, secure bool) { auth.ClearSessionCookie(w, secure) }

func (sessionCookies) Token(r *http.Request) string { return auth.TokenFromRequest(r) }

// profileImporter imports configuration files of the drivers that support
// it: OpenVPN .ovpn files and WireGuard wg-quick .conf files.
type profileImporter struct{}

func (profileImporter) Import(protocol domain.Protocol, text string) (api.ImportDraft, error) {
	switch protocol {
	case domain.ProtocolOpenVPN:
		return importOpenVPN(text)
	case domain.ProtocolWireGuard:
		return importWireGuard(text)
	}
	return api.ImportDraft{}, fmt.Errorf("import %q: %w", protocol, domain.ErrNotFound)
}

func importOpenVPN(text string) (api.ImportDraft, error) {
	result, err := openvpn.ImportOVPN(text)
	if err != nil {
		return api.ImportDraft{}, err
	}
	warnings := make([]api.ImportWarning, len(result.Warnings))
	for i, w := range result.Warnings {
		warnings[i] = api.ImportWarning{
			Code: w.Code, Severity: string(w.Severity), Directive: w.Directive, Line: w.Line, File: w.File, Message: w.Message,
		}
	}
	return api.ImportDraft{
		Settings: result.Settings, Secrets: result.Secrets, Warnings: warnings, Missing: result.Missing,
	}, nil
}

func importWireGuard(text string) (api.ImportDraft, error) {
	result, err := wireguard.ImportConf(text)
	if err != nil {
		return api.ImportDraft{}, err
	}
	warnings := make([]api.ImportWarning, len(result.Warnings))
	for i, w := range result.Warnings {
		warnings[i] = api.ImportWarning{
			Code: w.Code, Severity: string(w.Severity), Directive: w.Directive, Line: w.Line, Count: w.Count, Message: w.Message,
		}
	}
	return api.ImportDraft{
		Settings: result.Settings, Secrets: result.Secrets, Warnings: warnings, Missing: result.Missing,
	}, nil
}

func toCheckResults(results []netguard.CheckResult) []api.CheckResult {
	checks := make([]api.CheckResult, len(results))
	for i, r := range results {
		checks[i] = api.CheckResult{
			ID: r.ID, OK: r.OK, Warning: r.Warning, DetailCode: r.DetailCode, Params: r.Params, Detail: r.Detail, Hint: r.Hint,
		}
	}
	return checks
}
