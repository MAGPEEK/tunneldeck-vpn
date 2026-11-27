package api

import (
	"context"
	"net/http"
)

// hstsValue is the Strict-Transport-Security header of the HTTPS listener
// (one year, RFC 6797).
const hstsValue = "max-age=31536000"

type secureListenerKey struct{}

// SecureListener wraps the handler of the HTTPS listener (SPEC §8.1): every
// response carries Strict-Transport-Security, and the API marks the session
// cookie Secure and applies the remote login limit (SPEC §8.1).
func SecureListener(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", hstsValue)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), secureListenerKey{}, true)))
	})
}

// isSecureListener reports whether r arrived through SecureListener.
func isSecureListener(r *http.Request) bool {
	secure, _ := r.Context().Value(secureListenerKey{}).(bool)
	return secure
}

// loginClient describes the client of a login request. Every login on the
// HTTPS listener is remote, whatever the client address.
func loginClient(r *http.Request) LoginClient {
	return LoginClient{IP: clientIP(r), Remote: isSecureListener(r)}
}
