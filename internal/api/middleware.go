package api

import (
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CSRFHeader must be "1" on every request that is not GET or HEAD.
const CSRFHeader = "X-TunnelDeck-Request"

// statusRecorder remembers the response status for the request log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach Flush of the real writer.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// logRequests logs method, path, status and duration of every request:
// successful reads at debug level, everything else at info. Query strings
// and bodies are never logged.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		level := slog.LevelInfo
		if isSafeMethod(r.Method) && recorder.status < http.StatusBadRequest {
			level = slog.LevelDebug
		}
		slog.LogAttrs(r.Context(), level, "http request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", recorder.status),
			slog.Duration("duration", time.Since(start)),
		)
	})
}

// checkCSRF requires the CSRF header on unsafe methods and, when an Origin
// header is present, that its host equals the request's Host (RFC 6454).
func checkCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isSafeMethod(r.Method) {
			if r.Header.Get(CSRFHeader) != "1" {
				writeProblem(w, newProblem(http.StatusForbidden, CodeCSRF, "The request header "+CSRFHeader+" is missing."))
				return
			}
			if !originMatches(r) {
				writeProblem(w, newProblem(http.StatusForbidden, CodeCSRF, "The request origin does not match the host."))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

func originMatches(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// requireSession answers 401 unless the request carries a valid session.
func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.deps.Auth.Authenticate(s.deps.Cookies.Token(r)); !ok {
			writeProblem(w, newProblem(http.StatusUnauthorized, CodeUnauthenticated, "Sign in first."))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP is the address of the peer; forwarding headers are not trusted.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
