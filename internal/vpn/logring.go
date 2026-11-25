package vpn

import "tunneldeck/internal/domain"

// logRing keeps the most recent log lines, overwriting the oldest.
type logRing struct {
	lines []domain.LogEvent
	next  int // index the next line is written to
	full  bool
}

func newLogRing(capacity int) *logRing {
	return &logRing{lines: make([]domain.LogEvent, capacity)}
}

func (r *logRing) add(line domain.LogEvent) {
	r.lines[r.next] = line
	r.next = (r.next + 1) % len(r.lines)
	r.full = r.full || r.next == 0
}

// tail returns up to n of the newest lines, oldest first. n <= 0 returns
// every line.
func (r *logRing) tail(n int) []domain.LogEvent {
	ordered := r.ordered()
	if n > 0 && n < len(ordered) {
		ordered = ordered[len(ordered)-n:]
	}
	return ordered
}

func (r *logRing) ordered() []domain.LogEvent {
	if !r.full {
		return append([]domain.LogEvent(nil), r.lines[:r.next]...)
	}
	return append(append([]domain.LogEvent(nil), r.lines[r.next:]...), r.lines[:r.next]...)
}
