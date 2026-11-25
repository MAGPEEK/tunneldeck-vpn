package vpn

import (
	"fmt"
	"time"
)

// Retry backoff of SPEC §4.2.
const (
	minBackoff = 2 * time.Second
	maxBackoff = 60 * time.Second
	// backoffJitter spreads each delay by up to ±20 %.
	backoffJitter = 0.2
)

// backoffDelay returns the pause before the next attempt after failures
// consecutive failed attempts: 2 s doubling up to 60 s, jittered, never
// outside [2 s, 60 s]. random returns a value in [0, 1).
func backoffDelay(failures int, random func() float64) time.Duration {
	delay := minBackoff
	for range failures {
		if delay >= maxBackoff {
			break
		}
		delay *= 2
	}
	factor := 1 + backoffJitter*(2*random()-1)
	jittered := time.Duration(float64(min(delay, maxBackoff)) * factor)
	return min(max(jittered, minBackoff), maxBackoff)
}

// dayLayout names a calendar day.
const dayLayout = "2006-01-02"

// nextDailyRun returns the first time after now at the clock time hhmm
// ("HH:MM") in now's time zone whose calendar day is not lastRun. Days are
// counted on the calendar, so a DST change shifts nothing: a nonexistent
// time is normalised forward by time.Date and the day stays the same.
func nextDailyRun(now time.Time, hhmm, lastRun string) (time.Time, error) {
	at, err := time.Parse("15:04", hhmm)
	if err != nil {
		return time.Time{}, fmt.Errorf("daily reconnect time %q: %w", hhmm, err)
	}
	year, month, day := now.Date()
	for offset := 0; ; offset++ {
		candidate := time.Date(year, month, day+offset, at.Hour(), at.Minute(), 0, 0, now.Location())
		if candidate.After(now) && candidate.Format(dayLayout) != lastRun {
			return candidate, nil
		}
	}
}
