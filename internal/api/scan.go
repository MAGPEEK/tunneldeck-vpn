package api

import (
	"sync"
	"time"
)

// Scan detection (SPEC §8.2): scanThreshold requests for API paths that do
// not exist from one client within scanWindow are a possible scan. At most
// scanMaxClients clients are tracked.
const (
	scanThreshold  = 10
	scanWindow     = time.Minute
	scanMaxClients = 10000
)

// scanDetector counts requests for unknown API paths per client.
type scanDetector struct {
	mu      sync.Mutex
	clients map[string]*scanRecord
}

type scanRecord struct {
	start time.Time
	count int
}

func newScanDetector() *scanDetector {
	return &scanDetector{clients: make(map[string]*scanRecord)}
}

// notFound counts a request of client for an unknown path and returns how
// many requests to report as a possible scan: scanThreshold when the
// client reaches it, 1 for each request after that within the window, 0
// otherwise. The audit log merges the reports into one entry.
func (d *scanDetector) notFound(client string, now time.Time) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	record := d.clients[client]
	if record == nil || now.Sub(record.start) >= scanWindow {
		d.makeRoom(now)
		record = &scanRecord{start: now}
		d.clients[client] = record
	}
	record.count++
	switch {
	case record.count == scanThreshold:
		return scanThreshold
	case record.count > scanThreshold:
		return 1
	}
	return 0
}

// makeRoom drops expired records when the limit is reached, and every
// record when none has expired. The caller holds d.mu.
func (d *scanDetector) makeRoom(now time.Time) {
	if len(d.clients) < scanMaxClients {
		return
	}
	for client, record := range d.clients {
		if now.Sub(record.start) >= scanWindow {
			delete(d.clients, client)
		}
	}
	if len(d.clients) >= scanMaxClients {
		clear(d.clients)
	}
}
