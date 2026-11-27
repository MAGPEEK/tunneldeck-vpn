package store

import (
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"tunneldeck/internal/domain"
)

// The audit log (SPEC §8.2) lives in its own file rather than in
// settings.json: it changes on every login attempt and every rejected
// request, which an attacker controls, so it must neither rewrite the
// settings nor wait for their mutex.
const (
	AuditLogFileName = "audit-log.json"
	// AuditClassCapacity is the number of entries kept per class: sign-ins
	// and sign-outs, and security events. With one shared limit a burst of
	// attack events from many addresses could push every sign-in out.
	AuditClassCapacity = 500
	// DefaultAuditFlushDelay batches the writes of a burst of entries.
	DefaultAuditFlushDelay = 2 * time.Second

	auditLogSchemaVersion = 1
)

var auditLogMigrations = migrations{}

type auditLogDocument struct {
	SchemaVersion int   `json:"schemaVersion"`
	NextID        int64 `json:"nextId"`
	// Events are oldest first.
	Events []domain.AuditEvent `json:"events"`
}

// AuditLog keeps the newest AuditClassCapacity entries per class in
// audit-log.json. Entries are written in batches: at most flushDelay after
// they were recorded, and at Close. It is safe for concurrent use.
type AuditLog struct {
	mu         sync.Mutex
	dir        string
	fs         fileSystem
	spec       documentSpec
	flushDelay time.Duration
	doc        auditLogDocument
	pending    *time.Timer
	closed     bool
}

// OpenAuditLog loads audit-log.json from dataDir; a missing file yields an
// empty log. It fails, without modifying the file, when the file is
// corrupted or has a newer schema version.
func OpenAuditLog(dataDir string) (*AuditLog, error) {
	return openAuditLog(dataDir, osFileSystem{}, DefaultAuditFlushDelay)
}

// openAuditLog writes every entry at once when flushDelay is 0.
func openAuditLog(dataDir string, fsys fileSystem, flushDelay time.Duration) (*AuditLog, error) {
	if err := fsys.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("audit log: create data directory: %w", err)
	}
	a := &AuditLog{
		dir:        dataDir,
		fs:         fsys,
		spec:       documentSpec{AuditLogFileName, auditLogSchemaVersion, auditLogMigrations},
		flushDelay: flushDelay,
		doc:        auditLogDocument{SchemaVersion: auditLogSchemaVersion, NextID: 1},
	}
	if err := a.spec.load(fsys, dataDir, &a.doc); err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	a.doc.normalize()
	return a, nil
}

// normalize keeps IDs unique, counts positive and the classes within their
// capacity.
func (d *auditLogDocument) normalize() {
	d.SchemaVersion = auditLogSchemaVersion
	for i := range d.Events {
		d.Events[i].Count = max(d.Events[i].Count, 1)
		d.NextID = max(d.NextID, d.Events[i].ID+1)
	}
	d.trim(false)
	d.trim(true)
}

// trim drops the oldest entries of one class beyond AuditClassCapacity.
func (d *auditLogDocument) trim(security bool) {
	over := -AuditClassCapacity
	for _, e := range d.Events {
		if e.Type.IsSecurity() == security {
			over++
		}
	}
	d.Events = slices.DeleteFunc(d.Events, func(e domain.AuditEvent) bool {
		if over <= 0 || e.Type.IsSecurity() != security {
			return false
		}
		over--
		return true
	})
}

// add appends event with the next ID, or counts it in the entry it repeats
// (domain.AuditEvent.MergesInto), which then moves to the newest position.
func (d *auditLogDocument) add(event domain.AuditEvent) {
	if i := d.repeated(event); i >= 0 {
		earlier := d.Events[i]
		d.Events = slices.Delete(d.Events, i, i+1)
		event.Count += earlier.Count
		event.FirstTime = earlier.FirstTime
		if event.FirstTime.IsZero() {
			event.FirstTime = earlier.Time
		}
	}
	event.ID = d.NextID
	d.NextID++
	d.Events = append(d.Events, event)
	d.trim(event.Type.IsSecurity())
}

// repeated returns the index of the entry event repeats, or -1. Entries are
// in time order, so the search stops at the merge window.
func (d *auditLogDocument) repeated(event domain.AuditEvent) int {
	for i := len(d.Events) - 1; i >= 0; i-- {
		earlier := d.Events[i]
		if event.Time.Sub(earlier.Time) >= domain.AuditMergeWindow {
			return -1
		}
		if event.MergesInto(earlier) {
			return i
		}
	}
	return -1
}

// Record adds event. Write failures are logged; the entry stays in memory.
func (a *AuditLog) Record(event domain.AuditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	event.Time = event.Time.UTC()
	event.FirstTime = time.Time{}
	event.Count = max(event.Count, 1)
	a.doc.add(event)
	a.scheduleSave()
}

// AuditEvents returns the entries matching query, newest first.
func (a *AuditLog) AuditEvents(query domain.AuditQuery) domain.AuditPage {
	a.mu.Lock()
	defer a.mu.Unlock()
	page := domain.AuditPage{
		Events:         []domain.AuditEvent{},
		RecentWarnings: domain.RecentWarnings(a.doc.Events, query.WarningsSince),
	}
	for i := len(a.doc.Events) - 1; i >= 0; i-- {
		event := a.doc.Events[i]
		if !query.Matches(event) {
			continue
		}
		if query.Limit > 0 && len(page.Events) == query.Limit {
			page.HasMore = true
			break
		}
		page.Events = append(page.Events, event)
	}
	if latest, ok := domain.NewRemoteSignIn(a.doc.Events); ok {
		page.NewRemoteSignIn = &latest
	}
	return page
}

// Close writes pending entries. Entries recorded afterwards are written at
// once.
func (a *AuditLog) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	if a.pending == nil {
		return nil
	}
	a.pending.Stop()
	a.pending = nil
	return a.save()
}

// scheduleSave writes now when batching is off or the log is closed,
// otherwise once flushDelay after the first unsaved entry.
func (a *AuditLog) scheduleSave() {
	if a.closed || a.flushDelay <= 0 {
		logAuditSaveError(a.save())
		return
	}
	if a.pending == nil {
		a.pending = time.AfterFunc(a.flushDelay, a.flush)
	}
}

func (a *AuditLog) flush() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending == nil {
		return // Close wrote the entries
	}
	a.pending = nil
	logAuditSaveError(a.save())
}

func (a *AuditLog) save() error {
	if err := a.spec.save(a.fs, a.dir, a.doc); err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	return nil
}

func logAuditSaveError(err error) {
	if err != nil {
		slog.Error("keep the audit log", "error", err)
	}
}
