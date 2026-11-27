package api

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"tunneldeck/internal/domain"
)

// GET /api/audit: page sizes and the period of recentWarnings.
const (
	defaultAuditLimit  = 50
	maxAuditLimit      = 500
	recentWarningsSpan = 24 * time.Hour
)

type auditEventView struct {
	ID        int64                `json:"id"`
	Time      time.Time            `json:"time"`
	FirstTime *time.Time           `json:"firstTime,omitempty"`
	Type      domain.AuditType     `json:"type"`
	Severity  domain.AuditSeverity `json:"severity"`
	ClientIP  string               `json:"clientIp"`
	Access    domain.LoginAccess   `json:"access"`
	Username  string               `json:"username,omitempty"`
	Count     int                  `json:"count"`
}

type auditResponse struct {
	Entries []auditEventView `json:"entries"`
	HasMore bool             `json:"hasMore"`
	// RecentWarnings counts warning-level events of the last 24 h.
	RecentWarnings int `json:"recentWarnings"`
	// NewRemoteSignIn is the latest sign-in when it came through the
	// remote listener from an address not seen in earlier sign-ins.
	NewRemoteSignIn *auditEventView `json:"newRemoteSignIn,omitempty"`
}

func newAuditEventView(e domain.AuditEvent) auditEventView {
	view := auditEventView{
		ID: e.ID, Time: e.Time.UTC(), Type: e.Type, Severity: e.Type.Severity(), ClientIP: e.ClientIP, Access: e.Access,
		Username: e.Username, Count: e.Count,
	}
	if !e.FirstTime.IsZero() {
		first := e.FirstTime.UTC()
		view.FirstTime = &first
	}
	return view
}

// getAudit answers a page of the audit log, newest first: ?limit=1..500
// (default 50), ?before=<id> for older entries and ?filter=failures or
// ?filter=security.
func (s *Server) getAudit(w http.ResponseWriter, r *http.Request) {
	query, err := parseAuditQuery(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	query.WarningsSince = s.now().Add(-recentWarningsSpan)
	page := s.deps.Audit.AuditEvents(query)
	response := auditResponse{
		Entries: make([]auditEventView, 0, len(page.Events)), HasMore: page.HasMore, RecentWarnings: page.RecentWarnings,
	}
	for _, e := range page.Events {
		response.Entries = append(response.Entries, newAuditEventView(e))
	}
	if page.NewRemoteSignIn != nil {
		view := newAuditEventView(*page.NewRemoteSignIn)
		response.NewRemoteSignIn = &view
	}
	writeJSON(w, http.StatusOK, response)
}

func parseAuditQuery(r *http.Request) (domain.AuditQuery, error) {
	values := r.URL.Query()
	query := domain.AuditQuery{Limit: defaultAuditLimit}
	if text := values.Get("limit"); text != "" {
		n, err := strconv.Atoi(text)
		if err != nil || n < 1 || n > maxAuditLimit {
			return query, badRequestError{detail: "The parameter limit must be a whole number from 1 to 500."}
		}
		query.Limit = n
	}
	if text := values.Get("before"); text != "" {
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil || n < 1 {
			return query, badRequestError{detail: "The parameter before must be a positive whole number."}
		}
		query.Before = n
	}
	switch filter := domain.AuditFilter(values.Get("filter")); filter {
	case domain.AuditFilterAll, domain.AuditFilterFailures, domain.AuditFilterSecurity:
		query.Filter = filter
	default:
		return query, badRequestError{detail: "The parameter filter must be failures or security."}
	}
	return query, nil
}

// loginAuditType classifies the outcome of Auth.Login; ok is false for an
// internal error, which is not audited.
func loginAuditType(err error) (typ domain.AuditType, ok bool) {
	var rateLimit *RateLimitError
	switch {
	case err == nil:
		return domain.AuditSignedIn, true
	case errors.As(err, &rateLimit) && rateLimit.Remote:
		return domain.AuditRemoteLocked, true
	case errors.As(err, &rateLimit):
		return domain.AuditRateLimited, true
	case errors.Is(err, ErrInvalidCredentials):
		return domain.AuditWrongCredentials, true
	default:
		return "", false
	}
}

// audit records one event of r's client and logs it. username is kept only
// for sign-ins and sign-outs, never for failures or security events.
func (s *Server) audit(r *http.Request, typ domain.AuditType, username string) {
	s.auditCount(r, typ, username, 1)
}

// auditCount records count occurrences of an event of r's client.
func (s *Server) auditCount(r *http.Request, typ domain.AuditType, username string, count int) {
	if typ.IsFailure() || typ.IsSecurity() {
		username = ""
	}
	event := domain.AuditEvent{
		Time: s.now().UTC(), Type: typ, ClientIP: clientIP(r), Access: loginAccess(r), Username: username, Count: count,
	}
	s.deps.Audit.Record(event)
	logAuditEvent(r, event)
}

func loginAccess(r *http.Request) domain.LoginAccess {
	if isSecureListener(r) {
		return domain.LoginAccessRemote
	}
	return domain.LoginAccessLAN
}

// logAuditEvent writes the app log line of an audit event with the client
// IP: sign-ins and sign-outs at info, wrong credentials at warning. Merged
// security events go at debug, so a flood of them cannot flood the log;
// the rate limit already logs when a cooldown or lock starts. Never the
// username.
func logAuditEvent(r *http.Request, event domain.AuditEvent) {
	level := slog.LevelInfo
	switch {
	case event.Type == domain.AuditWrongCredentials:
		level = slog.LevelWarn
	case event.Type.IsSecurity():
		level = slog.LevelDebug
	}
	slog.LogAttrs(r.Context(), level, "audit",
		slog.String("event", string(event.Type)),
		slog.String("client", event.ClientIP),
		slog.String("access", string(event.Access)),
		slog.Int("count", event.Count),
	)
}
