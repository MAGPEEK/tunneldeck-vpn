package api

import (
	"context"
	"net/http"
	"net/netip"
)

// hstsValue is the Strict-Transport-Security header of the HTTPS listener
// (one year, RFC 6797).
const hstsValue = "max-age=31536000"

type secureListenerKey struct{}

// SecureListener wraps the handler of the HTTPS listener (SPEC §8.1): every
// response carries Strict-Transport-Security, and the API marks the session
// cookie Secure and applies the stricter login limit to remote clients.
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

// loginClient describes the client of a login request. Logins on the HTTPS
// listener from outside the local ranges get the strict limit.
func loginClient(r *http.Request) LoginClient {
	ip := clientIP(r)
	return LoginClient{IP: ip, Remote: isSecureListener(r) && !isLocalAddress(ip)}
}

// isLocalAddress reports whether ip is private (RFC 1918, RFC 4193),
// loopback or link-local. Unparseable addresses count as remote.
func isLocalAddress(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()
}
