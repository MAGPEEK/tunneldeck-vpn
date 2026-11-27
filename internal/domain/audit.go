package domain

import "time"

// AuditType is what an audit log entry records (SPEC §8.2).
type AuditType string

// Audit types of sign-ins and sign-outs.
const (
	// AuditSignedIn is a successful login.
	AuditSignedIn AuditType = "signedIn"
	// AuditWrongCredentials is a login with a wrong username or password;
	// the attempted username is never recorded.
	AuditWrongCredentials AuditType = "wrongCredentials"
	// AuditSignedOut is a sign-out of one session.
	AuditSignedOut AuditType = "signedOut"
	// AuditSignedOutEverywhere is "Sign out everywhere".
	AuditSignedOutEverywhere AuditType = "signedOutEverywhere"
)

// Audit types of security events.
const (
	// AuditRateLimited is a login rejected during the client's cooldown,
	// without checking the credentials.
	AuditRateLimited AuditType = "rateLimited"
	// AuditRemoteLocked is a login rejected while the remote listener is
	// locked for every client (SPEC §8.1).
	AuditRemoteLocked AuditType = "remoteLocked"
	// AuditRemoteLockStarted is the start of that lock; the client is the
	// one whose failure started it.
	AuditRemoteLockStarted AuditType = "remoteLockStarted"
	// AuditRemoteLockEnded is the end of that lock; it has no client.
	AuditRemoteLockEnded AuditType = "remoteLockEnded"
	// AuditCSRFRejected is a request refused by the CSRF check: a missing
	// request header or a foreign Origin, a sign of a cross-site or
	// scripted request.
	AuditCSRFRejected AuditType = "csrfRejected"
	// AuditBodyTooLarge is a request refused for a body over the limit.
	AuditBodyTooLarge AuditType = "bodyTooLarge"
	// AuditInvalidBody is a request refused for a body that is not the
	// expected JSON.
	AuditInvalidBody AuditType = "invalidBody"
	// AuditPossibleScan is a burst of requests for API paths that do not
	// exist from one client.
	AuditPossibleScan AuditType = "possibleScan"
)

// AuditSeverity ranks audit types: warnings are signs of an attack.
type AuditSeverity string

// Severities.
const (
	SeverityInfo    AuditSeverity = "info"
	SeverityNotice  AuditSeverity = "notice"
	SeverityWarning AuditSeverity = "warning"
)

// auditTypeInfo describes an audit type.
type auditTypeInfo struct {
	severity AuditSeverity
	// security puts the type in the security class, which has its own
	// capacity, so a flood of attack events never pushes sign-ins out.
	security bool
	// failure marks a failed or rejected login.
	failure bool
	// merged types are counted in one entry per client and listener while
	// they repeat within AuditMergeWindow.
	merged bool
}

var auditTypes = map[AuditType]auditTypeInfo{
	AuditSignedIn:            {severity: SeverityInfo},
	AuditWrongCredentials:    {severity: SeverityNotice, failure: true},
	AuditSignedOut:           {severity: SeverityInfo},
	AuditSignedOutEverywhere: {severity: SeverityInfo},
	AuditRateLimited:         {severity: SeverityWarning, security: true, failure: true, merged: true},
	AuditRemoteLocked:        {severity: SeverityWarning, security: true, failure: true, merged: true},
	AuditRemoteLockStarted:   {severity: SeverityWarning, security: true},
	AuditRemoteLockEnded:     {severity: SeverityInfo, security: true},
	AuditCSRFRejected:        {severity: SeverityWarning, security: true, merged: true},
	AuditBodyTooLarge:        {severity: SeverityWarning, security: true, merged: true},
	AuditInvalidBody:         {severity: SeverityNotice, security: true, merged: true},
	AuditPossibleScan:        {severity: SeverityWarning, security: true, merged: true},
}

// AuditMergeWindow is how long a repeated event is counted in the existing
// entry instead of starting a new one.
const AuditMergeWindow = 10 * time.Minute

// Severity of t; unknown types are notices.
func (t AuditType) Severity() AuditSeverity {
	if info, ok := auditTypes[t]; ok {
		return info.severity
	}
	return SeverityNotice
}

// IsSecurity reports whether t is a security event rather than a sign-in
// or sign-out.
func (t AuditType) IsSecurity() bool { return auditTypes[t].security }

// IsFailure reports whether t is a failed or rejected login.
func (t AuditType) IsFailure() bool { return auditTypes[t].failure }

// LoginAccess names the listener an audit entry came through.
type LoginAccess string

// Listeners.
const (
	LoginAccessLAN    LoginAccess = "lan"
	LoginAccessRemote LoginAccess = "remote"
)

// AuditEvent is one entry of the audit log. It never holds attempted
// usernames, passwords, request bodies or secrets.
type AuditEvent struct {
	// ID orders the entries; a later entry has a larger ID. A merged
	// repetition moves its entry to the newest position with a new ID.
	ID int64 `json:"id"`
	// Time is RFC 3339 UTC; for merged repetitions the latest.
	Time time.Time `json:"time"`
	// FirstTime is the first of merged repetitions; zero for a single one.
	FirstTime time.Time `json:"firstTime,omitzero"`
	Type      AuditType `json:"type"`
	// ClientIP is empty for events without a client (remoteLockEnded).
	ClientIP string      `json:"clientIp"`
	Access   LoginAccess `json:"access"`
	// Username is set for sign-ins and sign-outs only, never for failures.
	Username string `json:"username,omitempty"`
	// Count is the number of merged repetitions, at least 1.
	Count int `json:"count"`
}

// MergesInto reports whether e repeats earlier, so it is counted there.
func (e AuditEvent) MergesInto(earlier AuditEvent) bool {
	return auditTypes[e.Type].merged && e.Type == earlier.Type && e.ClientIP == earlier.ClientIP &&
		e.Access == earlier.Access && e.Time.Sub(earlier.Time) < AuditMergeWindow
}

// AuditFilter narrows an audit query.
type AuditFilter string

// Filters.
const (
	AuditFilterAll AuditFilter = ""
	// AuditFilterFailures keeps failed and rejected logins.
	AuditFilterFailures AuditFilter = "failures"
	// AuditFilterSecurity keeps security events.
	AuditFilterSecurity AuditFilter = "security"
)

// AuditQuery selects a page of the audit log, newest first.
type AuditQuery struct {
	// Limit is the page size; 0 returns every match.
	Limit int
	// Before, when > 0, returns only entries with a smaller ID.
	Before int64
	Filter AuditFilter
	// WarningsSince is the start of the period AuditPage.RecentWarnings
	// counts.
	WarningsSince time.Time
}

// Matches reports whether e belongs to the result of q, ignoring Limit.
func (q AuditQuery) Matches(e AuditEvent) bool {
	if q.Before > 0 && e.ID >= q.Before {
		return false
	}
	switch q.Filter {
	case AuditFilterFailures:
		return e.Type.IsFailure()
	case AuditFilterSecurity:
		return e.Type.IsSecurity()
	}
	return true
}

// AuditPage is one page of the audit log.
type AuditPage struct {
	// Events are newest first.
	Events []AuditEvent
	// HasMore is true when older entries match the query.
	HasMore bool
	// RecentWarnings counts the warning-level events (merged repetitions
	// included) since AuditQuery.WarningsSince, whatever the filter.
	RecentWarnings int
	// NewRemoteSignIn is the latest sign-in when it came through the
	// remote listener from an address no earlier sign-in in the log used.
	NewRemoteSignIn *AuditEvent
}

// RecentWarnings counts the warning-level events of events since since.
func RecentWarnings(events []AuditEvent, since time.Time) int {
	n := 0
	for _, e := range events {
		if e.Type.Severity() == SeverityWarning && !e.Time.Before(since) {
			n += e.Count
		}
	}
	return n
}

// NewRemoteSignIn returns the latest sign-in of events (oldest first) when
// it came through the remote listener from a client address that no earlier
// sign-in in events used.
func NewRemoteSignIn(events []AuditEvent) (AuditEvent, bool) {
	latest := -1
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Type == AuditSignedIn {
			latest = i
			break
		}
	}
	if latest < 0 || events[latest].Access != LoginAccessRemote {
		return AuditEvent{}, false
	}
	for _, earlier := range events[:latest] {
		if earlier.Type == AuditSignedIn && earlier.ClientIP == events[latest].ClientIP {
			return AuditEvent{}, false
		}
	}
	return events[latest], true
}
