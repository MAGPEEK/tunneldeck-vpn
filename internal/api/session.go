package api

import (
	"net/http"

	"tunneldeck/internal/domain"
)

type sessionResponse struct {
	SetupRequired bool   `json:"setupRequired"`
	Authenticated bool   `json:"authenticated"`
	Username      string `json:"username"`
	// RememberAvailable tells the UI to offer "stay signed in": only on the
	// LAN HTTP listener, never on the HTTPS listener (SPEC §8, §8.1).
	RememberAvailable bool `json:"rememberAvailable"`
}

type credentialsRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Remember bool   `json:"remember"`
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	username, authenticated := s.deps.Auth.Authenticate(s.deps.Cookies.Token(r))
	writeJSON(w, http.StatusOK, sessionResponse{
		SetupRequired:     s.deps.Auth.SetupRequired(),
		Authenticated:     authenticated,
		Username:          username,
		RememberAvailable: rememberAvailable(r),
	})
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	var body credentialsRequest
	if err := s.readJSON(w, r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	if err := s.deps.Auth.Setup(body.Username, body.Password); err != nil {
		writeError(w, r, err)
		return
	}
	writeNoContent(w)
}

// login ignores remember on the HTTPS listener, so remote sessions stay
// short.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var body loginRequest
	if err := s.readJSON(w, r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	remember := body.Remember && rememberAvailable(r)
	token, err := s.deps.Auth.Login(body.Username, body.Password, loginClient(r), remember)
	if typ, ok := loginAuditType(err); ok {
		s.audit(r, typ, body.Username)
	}
	if err != nil {
		writeError(w, r, err)
		return
	}
	s.deps.Cookies.Set(w, token, isSecureListener(r), remember)
	writeNoContent(w)
}

// logout clears the cookie also when the session could not be removed from
// the store.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	err := s.deps.Auth.Logout(s.deps.Cookies.Token(r))
	s.deps.Cookies.Clear(w, isSecureListener(r))
	s.audit(r, domain.AuditSignedOut, sessionUser(r))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeNoContent(w)
}

// logoutEverywhere ends every session, the caller's included.
func (s *Server) logoutEverywhere(w http.ResponseWriter, r *http.Request) {
	err := s.deps.Auth.LogoutEverywhere()
	s.deps.Cookies.Clear(w, isSecureListener(r))
	s.audit(r, domain.AuditSignedOutEverywhere, sessionUser(r))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeNoContent(w)
}

// rememberAvailable reports whether r may start a "stay signed in" session.
func rememberAvailable(r *http.Request) bool {
	return !isSecureListener(r)
}
