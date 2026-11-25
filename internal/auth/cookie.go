package auth

import "net/http"

// SessionCookieName is the name of the session cookie.
const SessionCookieName = "tunneldeck_session"

// SetSessionCookie stores token in a session cookie (no Max-Age, so the
// browser drops it when closed). Secure is set only when secure is true,
// i.e. when the UI is served over HTTPS.
func SetSessionCookie(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, sessionCookie(token, secure))
}

// ClearSessionCookie tells the browser to delete the session cookie.
func ClearSessionCookie(w http.ResponseWriter, secure bool) {
	cookie := sessionCookie("", secure)
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)
}

// TokenFromRequest returns the session token of r, or "" when there is none.
func TokenFromRequest(r *http.Request) string {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func sessionCookie(value string, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
}
