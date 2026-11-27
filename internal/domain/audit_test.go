package domain

import (
	"testing"
	"time"
)

func TestAuditTypeClassification(t *testing.T) {
	tests := []struct {
		typ      AuditType
		severity AuditSeverity
		security bool
		failure  bool
	}{
		{AuditSignedIn, SeverityInfo, false, false},
		{AuditWrongCredentials, SeverityNotice, false, true},
		{AuditSignedOut, SeverityInfo, false, false},
		{AuditSignedOutEverywhere, SeverityInfo, false, false},
		{AuditRateLimited, SeverityWarning, true, true},
		{AuditRemoteLocked, SeverityWarning, true, true},
		{AuditRemoteLockStarted, SeverityWarning, true, false},
		{AuditRemoteLockEnded, SeverityInfo, true, false},
		{AuditCSRFRejected, SeverityWarning, true, false},
		{AuditBodyTooLarge, SeverityWarning, true, false},
		{AuditInvalidBody, SeverityNotice, true, false},
		{AuditPossibleScan, SeverityWarning, true, false},
		{"unknown", SeverityNotice, false, false},
	}
	for _, tt := range tests {
		if got := tt.typ.Severity(); got != tt.severity {
			t.Errorf("%s severity = %s, want %s", tt.typ, got, tt.severity)
		}
		if got := tt.typ.IsSecurity(); got != tt.security {
			t.Errorf("%s security = %v, want %v", tt.typ, got, tt.security)
		}
		if got := tt.typ.IsFailure(); got != tt.failure {
			t.Errorf("%s failure = %v, want %v", tt.typ, got, tt.failure)
		}
	}
}

func TestAuditEventMergesInto(t *testing.T) {
	start := time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)
	earlier := AuditEvent{Type: AuditCSRFRejected, ClientIP: "10.0.0.1", Access: LoginAccessLAN, Time: start}
	at := func(e AuditEvent, d time.Duration) AuditEvent { e.Time = start.Add(d); return e }
	tests := []struct {
		name  string
		event AuditEvent
		want  bool
	}{
		{name: "same event soon after", event: at(earlier, time.Minute), want: true},
		{name: "after the window", event: at(earlier, AuditMergeWindow)},
		{name: "other client", event: AuditEvent{Type: AuditCSRFRejected, ClientIP: "10.0.0.2", Access: LoginAccessLAN, Time: start}},
		{name: "other listener", event: AuditEvent{Type: AuditCSRFRejected, ClientIP: "10.0.0.1", Access: LoginAccessRemote, Time: start}},
		{name: "other type", event: AuditEvent{Type: AuditPossibleScan, ClientIP: "10.0.0.1", Access: LoginAccessLAN, Time: start}},
	}
	for _, tt := range tests {
		if got := tt.event.MergesInto(earlier); got != tt.want {
			t.Errorf("%s: MergesInto = %v, want %v", tt.name, got, tt.want)
		}
	}
	for _, typ := range []AuditType{AuditWrongCredentials, AuditSignedIn, AuditRemoteLockStarted} {
		e := AuditEvent{Type: typ, ClientIP: "10.0.0.1", Access: LoginAccessLAN, Time: start}
		if e.MergesInto(e) {
			t.Errorf("%s merged; each of them must stay a single entry", typ)
		}
	}
}

func TestNewRemoteSignIn(t *testing.T) {
	signIn := func(ip string, access LoginAccess) AuditEvent {
		return AuditEvent{Type: AuditSignedIn, ClientIP: ip, Access: access}
	}
	failure := AuditEvent{Type: AuditWrongCredentials, ClientIP: "10.8.0.6", Access: LoginAccessRemote}
	tests := []struct {
		name   string
		events []AuditEvent
		want   string // client IP, "" = none
	}{
		{name: "empty"},
		{name: "first remote sign-in", events: []AuditEvent{signIn("10.8.0.6", LoginAccessRemote)}, want: "10.8.0.6"},
		{name: "latest is LAN", events: []AuditEvent{signIn("10.8.0.6", LoginAccessRemote), signIn("192.168.1.2", LoginAccessLAN)}},
		{name: "known address", events: []AuditEvent{signIn("10.8.0.6", LoginAccessLAN), signIn("10.8.0.6", LoginAccessRemote)}},
		{name: "only failures before", events: []AuditEvent{failure, signIn("10.8.0.6", LoginAccessRemote)}, want: "10.8.0.6"},
		{name: "later failures ignored", events: []AuditEvent{signIn("10.8.0.7", LoginAccessRemote), failure}, want: "10.8.0.7"},
		{name: "other address earlier", events: []AuditEvent{signIn("10.8.0.5", LoginAccessRemote), signIn("10.8.0.7", LoginAccessRemote)}, want: "10.8.0.7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := NewRemoteSignIn(tt.events)
			if ok != (tt.want != "") || got.ClientIP != tt.want {
				t.Fatalf("NewRemoteSignIn = %+v %v, want %q", got, ok, tt.want)
			}
		})
	}
}

func TestRecentWarnings(t *testing.T) {
	since := time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)
	events := []AuditEvent{
		{Type: AuditCSRFRejected, Time: since.Add(-time.Second), Count: 4},
		{Type: AuditCSRFRejected, Time: since, Count: 2},
		{Type: AuditPossibleScan, Time: since.Add(time.Hour), Count: 30},
		{Type: AuditWrongCredentials, Time: since.Add(time.Hour), Count: 1},
		{Type: AuditRemoteLockEnded, Time: since.Add(time.Hour), Count: 1},
	}
	if got := RecentWarnings(events, since); got != 32 {
		t.Fatalf("RecentWarnings = %d, want 32", got)
	}
}

func TestAuditQueryMatches(t *testing.T) {
	signIn := AuditEvent{ID: 5, Type: AuditSignedIn}
	csrf := AuditEvent{ID: 5, Type: AuditCSRFRejected}
	limited := AuditEvent{ID: 5, Type: AuditRateLimited}
	tests := []struct {
		name  string
		query AuditQuery
		event AuditEvent
		want  bool
	}{
		{"all", AuditQuery{}, signIn, true},
		{"before later", AuditQuery{Before: 6}, signIn, true},
		{"before same", AuditQuery{Before: 5}, signIn, false},
		{"failures: sign-in", AuditQuery{Filter: AuditFilterFailures}, signIn, false},
		{"failures: rate limited", AuditQuery{Filter: AuditFilterFailures}, limited, true},
		{"failures: csrf", AuditQuery{Filter: AuditFilterFailures}, csrf, false},
		{"security: csrf", AuditQuery{Filter: AuditFilterSecurity}, csrf, true},
		{"security: sign-in", AuditQuery{Filter: AuditFilterSecurity}, signIn, false},
	}
	for _, tt := range tests {
		if got := tt.query.Matches(tt.event); got != tt.want {
			t.Errorf("%s: Matches = %v, want %v", tt.name, got, tt.want)
		}
	}
}
