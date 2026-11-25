package vpn

import (
	"slices"
	"strconv"
	"testing"
	"time"
	_ "time/tzdata" // Europe/Berlin on every test machine

	"tunneldeck/internal/domain"
)

func berlin(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Fatalf("LoadLocation: %v", err)
	}
	return loc
}

func TestBackoffDelay(t *testing.T) {
	tests := []struct {
		failures int
		random   float64
		want     time.Duration
	}{
		{0, 0.5, 2 * time.Second},
		{1, 0.5, 4 * time.Second},
		{4, 0.5, 32 * time.Second},
		{5, 0.5, 60 * time.Second},
		{50, 0.5, 60 * time.Second},
		{0, 0, 2 * time.Second}, // jitter never goes below the minimum
		{1, 0, 3200 * time.Millisecond},
		{5, 0, 48 * time.Second},
		{1, 0.75, 4400 * time.Millisecond},
		{5, 0.99, 60 * time.Second}, // nor above the maximum
	}
	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.failures), func(t *testing.T) {
			got := backoffDelay(tt.failures, func() float64 { return tt.random })
			if got != tt.want {
				t.Errorf("backoffDelay(%d, %v) = %v, want %v", tt.failures, tt.random, got, tt.want)
			}
		})
	}
}

func TestNextDailyRun(t *testing.T) {
	loc := berlin(t)
	at := func(year int, month time.Month, day, hour, minute int) time.Time {
		return time.Date(year, month, day, hour, minute, 0, 0, loc)
	}
	tests := []struct {
		name    string
		now     time.Time
		hhmm    string
		lastRun string
		want    time.Time
	}{
		{name: "later today", now: at(2026, 11, 25, 3, 0), hhmm: "04:00", want: at(2026, 11, 25, 4, 0)},
		{name: "passed today", now: at(2026, 11, 25, 5, 0), hhmm: "04:00", want: at(2026, 11, 26, 4, 0)},
		{name: "exactly now", now: at(2026, 11, 25, 4, 0), hhmm: "04:00", want: at(2026, 11, 26, 4, 0)},
		{
			name: "already ran today", now: at(2026, 11, 25, 4, 30), hhmm: "05:00",
			lastRun: "2026-11-25", want: at(2026, 11, 26, 5, 0),
		},
		{name: "month end", now: at(2026, 11, 30, 23, 0), hhmm: "00:15", want: at(2026, 12, 1, 0, 15)},
		{
			name: "nonexistent time on the spring change", now: at(2026, 3, 29, 0, 0), hhmm: "02:30",
			want: time.Date(2026, 3, 29, 3, 30, 0, 0, loc),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nextDailyRun(tt.now, tt.hhmm, tt.lastRun)
			if err != nil {
				t.Fatalf("nextDailyRun: %v", err)
			}
			if !got.Equal(tt.want) {
				t.Errorf("nextDailyRun = %v, want %v", got, tt.want)
			}
		})
	}
	if _, err := nextDailyRun(at(2026, 11, 25, 3, 0), "25:00", ""); err == nil {
		t.Error("nextDailyRun accepted 25:00")
	}
}

func TestManagerDailyReconnect(t *testing.T) {
	h := newManagerHarnessAt(t, time.Date(2026, 11, 25, 3, 0, 0, 0, berlin(t)))
	h.store.setDaily("a", domain.DailyReconnect{Enabled: true, Time: "04:00"})
	first := h.connectUp("a", "10.66.0.2")
	if pending := h.pending(); !slices.Equal(pending, []time.Duration{time.Hour}) {
		t.Fatalf("pending = %v, want the reconnect in 1h", pending)
	}
	h.advance(time.Hour)
	h.waitLog(reasonDailyReconnect)
	if e := h.waitState(domain.StateReconnecting); e.Message != reasonDailyReconnect {
		t.Errorf("reconnecting event = %+v", e)
	}
	first.awaitStop(t)
	second := h.nextDriver()
	second.emit(connectedEvent("10.66.0.2"))
	h.waitState(domain.StateConnected)
	if pending := h.pending(); !slices.Equal(pending, []time.Duration{24 * time.Hour}) {
		t.Fatalf("pending = %v, want the next run in 24h", pending)
	}

	// Moving the time to later today must not reconnect twice on one day.
	h.store.setDaily("a", domain.DailyReconnect{Enabled: true, Time: "05:00"})
	h.m.ProfileChanged("a")
	if pending := h.pending(); !slices.Equal(pending, []time.Duration{25 * time.Hour}) {
		t.Fatalf("pending = %v, want tomorrow 05:00", pending)
	}
	h.store.setDaily("a", domain.DailyReconnect{Enabled: false, Time: "05:00"})
	h.m.ProfileChanged("a")
	if pending := h.pending(); len(pending) != 0 {
		t.Errorf("pending after switching it off = %v", pending)
	}
	h.assertNoDriver()
}

func TestManagerDailyReconnectSkippedWhenNotConnected(t *testing.T) {
	h := newManagerHarnessAt(t, time.Date(2026, 11, 25, 3, 0, 0, 0, berlin(t)))
	h.store.setDaily("a", domain.DailyReconnect{Enabled: true, Time: "04:00"})
	h.connect("a")
	d := h.nextDriver()
	h.waitState(domain.StateConnecting)
	h.advance(time.Hour)
	h.waitLog("scheduled daily reconnect skipped")
	h.assertNoDriver()
	select {
	case <-d.stopped:
		t.Error("a tunnel that was still connecting was restarted")
	default:
	}
	if pending := h.pending(); !slices.Equal(pending, []time.Duration{24 * time.Hour}) {
		t.Errorf("pending = %v, want tomorrow", pending)
	}
	if err := h.m.Disconnect(ctx); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if pending := h.pending(); len(pending) != 0 {
		t.Errorf("pending after disconnect = %v", pending)
	}
}

func TestManagerDailyReconnectAcrossDST(t *testing.T) {
	tests := []struct {
		name  string
		start time.Time
		want  time.Duration
	}{
		{name: "spring forward", start: time.Date(2026, 3, 28, 3, 0, 0, 0, berlin(t)), want: 23 * time.Hour},
		{name: "fall back", start: time.Date(2026, 10, 24, 3, 0, 0, 0, berlin(t)), want: 25 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newManagerHarnessAt(t, tt.start)
			h.store.setDaily("a", domain.DailyReconnect{Enabled: true, Time: "04:00"})
			h.connectUp("a", "10.66.0.2")
			h.advance(time.Hour)
			h.nextDriver().emit(connectedEvent("10.66.0.2"))
			h.waitState(domain.StateConnected)
			if pending := h.pending(); !slices.Equal(pending, []time.Duration{tt.want}) {
				t.Errorf("pending = %v, want %v until 04:00 local time", pending, tt.want)
			}
		})
	}
}

func TestLogRing(t *testing.T) {
	ring := newLogRing(3)
	texts := func(lines []domain.LogEvent) []string {
		var out []string
		for _, line := range lines {
			out = append(out, line.Text)
		}
		return out
	}
	ring.add(domain.LogEvent{Text: "1"})
	ring.add(domain.LogEvent{Text: "2"})
	if got := texts(ring.tail(0)); !slices.Equal(got, []string{"1", "2"}) {
		t.Errorf("tail before wrapping = %v", got)
	}
	for _, text := range []string{"3", "4", "5"} {
		ring.add(domain.LogEvent{Text: text})
	}
	tests := []struct {
		n    int
		want []string
	}{
		{0, []string{"3", "4", "5"}},
		{2, []string{"4", "5"}},
		{10, []string{"3", "4", "5"}},
		{-1, []string{"3", "4", "5"}},
	}
	for _, tt := range tests {
		if got := texts(ring.tail(tt.n)); !slices.Equal(got, tt.want) {
			t.Errorf("tail(%d) = %v, want %v", tt.n, got, tt.want)
		}
	}
}
