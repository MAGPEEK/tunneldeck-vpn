package domain

import "time"

// RememberedSession is a "stay signed in" session that survives a restart
// (SPEC §8). TokenHash is the hex SHA-256 of the session token; the token
// itself is never stored. Times are UTC.
type RememberedSession struct {
	TokenHash  string    `json:"tokenHash"`
	Username   string    `json:"username"`
	CreatedAt  time.Time `json:"createdAt"`
	LastUsedAt time.Time `json:"lastUsedAt"`
	ClientIP   string    `json:"clientIp"`
}
