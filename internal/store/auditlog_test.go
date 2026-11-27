package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tunneldeck/internal/domain"
)

var auditStart = time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)

func openTestAuditLog(t *testing.T, dir string, flushDelay time.Duration) *AuditLog {
	t.Helper()
	a, err := openAuditLog(dir, osFileSystem{}, flushDelay)
	if err != nil {
		t.Fatalf("openAuditLog: %v", err)
	}
	return a
}

func auditEvent(minute int, typ domain.AuditType, ip string, access domain.LoginAccess) domain.AuditEvent {
	return domain.AuditEvent{Time: auditStart.Add(time.Duration(minute) * time.Minute), Type: typ, ClientIP: ip, Access: access}
}

func readAuditLogFile(t *testing.T, dir string) auditLogDocument {
	t.Helper()
	var doc auditLogDocument
	if err := json.Unmarshal(readFile(t, dir, AuditLogFileName), &doc); err != nil {
		t.Fatalf("decode %s: %v", AuditLogFileName, err)
	}
	return doc
}

func eventIDs(events []domain.AuditEvent) []int64 {
	ids := []int64{}
	for _, e := range events {
		ids = append(ids, e.ID)
	}
	return ids
}

func TestAuditLogRecordAndReload(t *testing.T) {
	dir := t.TempDir()
	a := openTestAuditLog(t, dir, 0)
	signIn := auditEvent(0, domain.AuditSignedIn, "192.168.1.20", domain.LoginAccessLAN)
	signIn.Username = "admin"
	signIn.Time = signIn.Time.In(time.FixedZone("CET", 3600))
	a.Record(signIn)
	a.Record(auditEvent(1, domain.AuditWrongCredentials, "10.8.0.6", domain.LoginAccessRemote))

	doc := readAuditLogFile(t, dir)
	if doc.SchemaVersion != 1 || doc.NextID != 3 || len(doc.Events) != 2 {
		t.Fatalf("file = %+v", doc)
	}
	content := string(readFile(t, dir, AuditLogFileName))
	if !strings.Contains(content, `"time": "2026-11-27T09:00:00Z"`) || strings.Contains(content, "firstTime") {
		t.Errorf("file content: %s", content)
	}
	page := openTestAuditLog(t, dir, 0).AuditEvents(domain.AuditQuery{})
	want := []domain.AuditEvent{
		{ID: 2, Time: auditStart.Add(time.Minute), Type: domain.AuditWrongCredentials, ClientIP: "10.8.0.6", Access: domain.LoginAccessRemote, Count: 1},
		{ID: 1, Time: auditStart, Type: domain.AuditSignedIn, ClientIP: "192.168.1.20", Access: domain.LoginAccessLAN, Username: "admin", Count: 1},
	}
	if fmt.Sprint(page.Events) != fmt.Sprint(want) || page.HasMore {
		t.Fatalf("reloaded page = %+v, want %+v", page, want)
	}
	assertNoTempFiles(t, dir)
}

func TestAuditLogMergesRepeatedEvents(t *testing.T) {
	a := openTestAuditLog(t, t.TempDir(), 0)
	a.Record(auditEvent(0, domain.AuditCSRFRejected, "10.0.0.1", domain.LoginAccessLAN))
	a.Record(auditEvent(1, domain.AuditCSRFRejected, "10.0.0.2", domain.LoginAccessLAN))
	a.Record(auditEvent(2, domain.AuditSignedIn, "192.168.1.20", domain.LoginAccessLAN))
	a.Record(auditEvent(3, domain.AuditCSRFRejected, "10.0.0.1", domain.LoginAccessLAN))
	scan := auditEvent(4, domain.AuditPossibleScan, "10.0.0.1", domain.LoginAccessLAN)
	scan.Count = 10
	a.Record(scan)
	a.Record(auditEvent(5, domain.AuditPossibleScan, "10.0.0.1", domain.LoginAccessLAN))
	a.Record(auditEvent(20, domain.AuditCSRFRejected, "10.0.0.1", domain.LoginAccessLAN)) // after the window

	events := a.AuditEvents(domain.AuditQuery{}).Events
	got := []string{}
	for _, e := range events {
		got = append(got, fmt.Sprintf("%d %s %s x%d first=%s last=%s", e.ID, e.Type, e.ClientIP, e.Count,
			e.FirstTime.Format("15:04"), e.Time.Format("15:04")))
	}
	want := []string{
		"7 csrfRejected 10.0.0.1 x1 first=00:00 last=09:20",
		"6 possibleScan 10.0.0.1 x11 first=09:04 last=09:05",
		"4 csrfRejected 10.0.0.1 x2 first=09:00 last=09:03",
		"3 signedIn 192.168.1.20 x1 first=00:00 last=09:02",
		"2 csrfRejected 10.0.0.2 x1 first=00:00 last=09:01",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("entries:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestAuditLogCapacityPerClass(t *testing.T) {
	dir := t.TempDir()
	a := openTestAuditLog(t, dir, 0)
	for i := range 3 {
		a.Record(auditEvent(i, domain.AuditSignedIn, "192.168.1.20", domain.LoginAccessLAN))
	}
	for i := range AuditClassCapacity + 20 {
		a.Record(auditEvent(3, domain.AuditCSRFRejected, fmt.Sprintf("10.%d.%d.1", i/250, i%250), domain.LoginAccessLAN))
	}
	page := a.AuditEvents(domain.AuditQuery{})
	signIns, security := 0, 0
	for _, e := range page.Events {
		if e.Type.IsSecurity() {
			security++
		} else {
			signIns++
		}
	}
	if signIns != 3 || security != AuditClassCapacity {
		t.Fatalf("kept %d sign-ins and %d security events", signIns, security)
	}
	for range AuditClassCapacity + 20 {
		a.Record(auditEvent(4, domain.AuditWrongCredentials, "10.0.0.1", domain.LoginAccessLAN))
	}
	if doc := readAuditLogFile(t, dir); len(doc.Events) != 2*AuditClassCapacity {
		t.Fatalf("file holds %d entries, want %d", len(doc.Events), 2*AuditClassCapacity)
	}
}

func TestAuditLogPaging(t *testing.T) {
	a := openTestAuditLog(t, t.TempDir(), 0)
	types := []domain.AuditType{
		domain.AuditSignedIn, domain.AuditWrongCredentials, domain.AuditSignedOut, domain.AuditRateLimited,
		domain.AuditCSRFRejected, domain.AuditRemoteLocked, domain.AuditSignedOutEverywhere,
	}
	for i, typ := range types {
		a.Record(auditEvent(i, typ, "10.0.0.1", domain.LoginAccessLAN))
	}
	tests := []struct {
		name    string
		query   domain.AuditQuery
		ids     []int64
		hasMore bool
	}{
		{name: "all", query: domain.AuditQuery{}, ids: []int64{7, 6, 5, 4, 3, 2, 1}},
		{name: "first page", query: domain.AuditQuery{Limit: 3}, ids: []int64{7, 6, 5}, hasMore: true},
		{name: "next page", query: domain.AuditQuery{Limit: 3, Before: 5}, ids: []int64{4, 3, 2}, hasMore: true},
		{name: "last page", query: domain.AuditQuery{Limit: 3, Before: 2}, ids: []int64{1}},
		{name: "exactly full", query: domain.AuditQuery{Limit: 1, Before: 2}, ids: []int64{1}},
		{name: "failures", query: domain.AuditQuery{Filter: domain.AuditFilterFailures}, ids: []int64{6, 4, 2}},
		{name: "failures paged", query: domain.AuditQuery{Limit: 2, Filter: domain.AuditFilterFailures}, ids: []int64{6, 4}, hasMore: true},
		{name: "security", query: domain.AuditQuery{Filter: domain.AuditFilterSecurity}, ids: []int64{6, 5, 4}},
		{name: "security before", query: domain.AuditQuery{Before: 5, Filter: domain.AuditFilterSecurity}, ids: []int64{4}},
		{name: "before the first", query: domain.AuditQuery{Limit: 2, Before: 1}, ids: []int64{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page := a.AuditEvents(tt.query)
			if ids := eventIDs(page.Events); fmt.Sprint(ids) != fmt.Sprint(tt.ids) || page.HasMore != tt.hasMore {
				t.Fatalf("ids = %v hasMore %v, want %v %v", ids, page.HasMore, tt.ids, tt.hasMore)
			}
		})
	}
}

func TestAuditLogPageSummaries(t *testing.T) {
	a := openTestAuditLog(t, t.TempDir(), 0)
	a.Record(auditEvent(0, domain.AuditCSRFRejected, "10.0.0.1", domain.LoginAccessLAN))
	a.Record(auditEvent(60, domain.AuditRateLimited, "10.0.0.1", domain.LoginAccessLAN))
	a.Record(auditEvent(61, domain.AuditRateLimited, "10.0.0.1", domain.LoginAccessLAN))
	a.Record(auditEvent(62, domain.AuditSignedIn, "10.8.0.6", domain.LoginAccessRemote))
	page := a.AuditEvents(domain.AuditQuery{Limit: 1, Filter: domain.AuditFilterFailures, WarningsSince: auditStart.Add(time.Minute)})
	if page.RecentWarnings != 2 {
		t.Errorf("RecentWarnings = %d, want 2", page.RecentWarnings)
	}
	if page.NewRemoteSignIn == nil || page.NewRemoteSignIn.ClientIP != "10.8.0.6" {
		t.Errorf("NewRemoteSignIn = %+v", page.NewRemoteSignIn)
	}
	a.Record(auditEvent(63, domain.AuditSignedIn, "10.8.0.6", domain.LoginAccessRemote))
	if page := a.AuditEvents(domain.AuditQuery{}); page.NewRemoteSignIn != nil {
		t.Errorf("known address reported: %+v", page.NewRemoteSignIn)
	}
}

func TestAuditLogBatchesWrites(t *testing.T) {
	dir := t.TempDir()
	a := openTestAuditLog(t, dir, time.Hour)
	a.Record(auditEvent(0, domain.AuditSignedIn, "10.0.0.1", domain.LoginAccessLAN))
	if _, err := os.Stat(filepath.Join(dir, AuditLogFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("written before the flush delay: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if doc := readAuditLogFile(t, dir); len(doc.Events) != 1 {
		t.Fatalf("Close wrote %d entries", len(doc.Events))
	}
	a.Record(auditEvent(1, domain.AuditSignedOut, "10.0.0.1", domain.LoginAccessLAN))
	if doc := readAuditLogFile(t, dir); len(doc.Events) != 2 {
		t.Fatalf("an entry after Close was not written at once: %d entries", len(doc.Events))
	}
}

func TestAuditLogFlushesAfterTheDelay(t *testing.T) {
	dir := t.TempDir()
	a := openTestAuditLog(t, dir, 10*time.Millisecond)
	defer func() { _ = a.Close() }()
	a.Record(auditEvent(0, domain.AuditSignedIn, "10.0.0.1", domain.LoginAccessLAN))
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, AuditLogFileName)); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("not written after the flush delay")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAuditLogConcurrentRecords(t *testing.T) {
	dir := t.TempDir()
	a := openTestAuditLog(t, dir, time.Millisecond)
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			a.Record(auditEvent(i, domain.AuditWrongCredentials, fmt.Sprintf("10.0.0.%d", i), domain.LoginAccessLAN))
			a.AuditEvents(domain.AuditQuery{Limit: 5})
		})
	}
	wg.Wait()
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if doc := readAuditLogFile(t, dir); len(doc.Events) != 50 || doc.NextID != 51 {
		t.Fatalf("file has %d entries, next ID %d", len(doc.Events), doc.NextID)
	}
}

func TestOpenAuditLogRefusesBadFiles(t *testing.T) {
	tests := []struct {
		name, content, want string
	}{
		{name: "corrupted", content: `{"schemaVersion":1,"events":[`, want: "corrupted"},
		{name: "newer schema", content: `{"schemaVersion":2,"events":[]}`, want: "newer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, AuditLogFileName, tt.content)
			_, err := openAuditLog(dir, osFileSystem{}, 0)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
			if got := string(readFile(t, dir, AuditLogFileName)); got != tt.content {
				t.Fatalf("file was modified: %s", got)
			}
		})
	}
}

func TestOpenAuditLogRepairsIDsAndCounts(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, AuditLogFileName,
		`{"schemaVersion":1,"nextId":1,"events":[{"id":7,"time":"2026-11-27T09:00:00Z","type":"signedIn","clientIp":"10.0.0.1","access":"lan"}]}`)
	a := openTestAuditLog(t, dir, 0)
	a.Record(auditEvent(1, domain.AuditSignedOut, "10.0.0.1", domain.LoginAccessLAN))
	events := a.AuditEvents(domain.AuditQuery{}).Events
	if events[0].ID != 8 || events[1].Count != 1 {
		t.Fatalf("events = %+v", events)
	}
}

func TestAuditLogWriteFailureKeepsEntries(t *testing.T) {
	dir := t.TempDir()
	fsys := &faultyFS{failStep: "rename"}
	a, err := openAuditLog(dir, fsys, 0)
	if err != nil {
		t.Fatalf("openAuditLog: %v", err)
	}
	a.Record(auditEvent(0, domain.AuditSignedIn, "10.0.0.1", domain.LoginAccessLAN))
	assertNoTempFiles(t, dir)
	if events := a.AuditEvents(domain.AuditQuery{}).Events; len(events) != 1 {
		t.Fatalf("entries in memory = %d", len(events))
	}
	fsys.failStep = ""
	a.Record(auditEvent(1, domain.AuditSignedOut, "10.0.0.1", domain.LoginAccessLAN))
	if doc := readAuditLogFile(t, dir); len(doc.Events) != 2 {
		t.Fatalf("file has %d entries after recovery", len(doc.Events))
	}
}
