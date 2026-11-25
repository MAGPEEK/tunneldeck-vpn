package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

// Problem codes: the stable, machine-readable "code" member.
const (
	CodeBadRequest         = "bad_request"
	CodeUnauthenticated    = "unauthenticated"
	CodeInvalidCredentials = "invalid_credentials"
	CodeCSRF               = "csrf"
	CodeNotFound           = "not_found"
	CodeMethodNotAllowed   = "method_not_allowed"
	CodeConflict           = "conflict"
	CodeSetupDone          = "setup_done"
	CodeValidationFailed   = "validation_failed"
	CodeRateLimited        = "rate_limited"
	CodeInternal           = "internal"
	CodeFirewallFailed     = "firewall_failed"
	CodeRemoteAccessFailed = "remote_access_failed"
	CodeUnavailable        = "unavailable"
	CodeGone               = "gone"
)

const problemContentType = "application/problem+json"

// problem is an RFC 9457 problem details object; Code and Fields are
// extension members.
type problem struct {
	Type   string            `json:"type"`
	Title  string            `json:"title"`
	Status int               `json:"status"`
	Detail string            `json:"detail,omitempty"`
	Code   string            `json:"code"`
	Fields map[string]string `json:"fields,omitempty"`
}

func newProblem(status int, code, detail string) problem {
	return problem{Type: "about:blank", Title: http.StatusText(status), Status: status, Detail: detail, Code: code}
}

func writeProblem(w http.ResponseWriter, p problem) {
	w.Header().Set("Content-Type", problemContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(p.Status)
	if err := json.NewEncoder(w).Encode(p); err != nil {
		slog.Debug("write problem response", "error", err)
	}
}

// writeError maps err to a problem response. Messages of domain errors
// never carry submitted values, so they are safe to return; unknown errors
// are logged and answered with a generic detail.
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	var validation *domain.ValidationError
	var rateLimit *RateLimitError
	var badRequest badRequestError
	switch {
	case errors.As(err, &badRequest):
		writeProblem(w, newProblem(http.StatusBadRequest, CodeBadRequest, badRequest.detail))
	case errors.As(err, &validation):
		p := newProblem(http.StatusUnprocessableEntity, CodeValidationFailed, "The request contains invalid fields.")
		p.Fields = validation.Fields
		writeProblem(w, p)
	case errors.As(err, &rateLimit):
		seconds := max(1, int(math.Ceil(rateLimit.RetryAfter.Seconds())))
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		writeProblem(w, newProblem(http.StatusTooManyRequests, CodeRateLimited, "Too many failed logins. Try again later."))
	case errors.Is(err, ErrInvalidCredentials):
		writeProblem(w, newProblem(http.StatusUnauthorized, CodeInvalidCredentials, "The username or password is wrong."))
	case errors.Is(err, domain.ErrSetupAlreadyDone):
		writeProblem(w, newProblem(http.StatusConflict, CodeSetupDone, "Setup has already been done."))
	case errors.Is(err, domain.ErrNotFound):
		writeProblem(w, newProblem(http.StatusNotFound, CodeNotFound, "The resource does not exist."))
	case errors.Is(err, domain.ErrConflict):
		detail := "The request conflicts with the current state."
		var c conflictError
		if errors.As(err, &c) {
			detail = c.detail
		}
		writeProblem(w, newProblem(http.StatusConflict, CodeConflict, detail))
	case errors.Is(err, vpn.ErrClosed):
		writeProblem(w, newProblem(http.StatusServiceUnavailable, CodeUnavailable, "The server is shutting down."))
	default:
		slog.Error("request failed", "method", r.Method, "path", r.URL.Path, "error", err)
		writeProblem(w, newProblem(http.StatusInternalServerError, CodeInternal, "An internal error occurred."))
	}
}

// conflictError is a domain.ErrConflict with a detail for the client.
type conflictError struct{ detail string }

func (e conflictError) Error() string { return e.detail }
func (e conflictError) Unwrap() error { return domain.ErrConflict }
