package api

import "net/http"

// contentSecurityPolicy allows only the app's own scripts, styles, fonts,
// images (plus data: URIs) and same-origin fetch/EventSource; nothing may
// frame the UI (SPEC §8). The SPA has no inline scripts, <style> elements or
// inline event handlers; React's style props go through the CSSOM, which
// style-src does not restrict.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// permissionsPolicy switches off powerful browser features the UI never
// uses, also for anything it might embed.
const permissionsPolicy = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), " +
	"microphone=(), payment=(), usb=()"

// securityHeaders are sent with every response of both listeners.
var securityHeaders = [][2]string{
	{"Content-Security-Policy", contentSecurityPolicy},
	{"X-Frame-Options", "DENY"},
	{"X-Content-Type-Options", "nosniff"},
	{"Referrer-Policy", "no-referrer"},
	{"Permissions-Policy", permissionsPolicy},
	{"Cross-Origin-Opener-Policy", "same-origin"},
	{"Cross-Origin-Resource-Policy", "same-origin"},
}

// SecurityHeaders sets the security headers of SPEC §8 on every response of
// next: the API, the SPA and their error responses. Wrap the router both
// listeners share; SecureListener adds HSTS on the HTTPS listener.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		for _, h := range securityHeaders {
			header.Set(h[0], h[1])
		}
		next.ServeHTTP(w, r)
	})
}

// noStore keeps every API response out of caches (RFC 9111); handlers that
// write a body set it again.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
