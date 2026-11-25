package api

import "net/http"

type sessionResponse struct {
	SetupRequired bool   `json:"setupRequired"`
	Authenticated bool   `json:"authenticated"`
	Username      string `json:"username"`
}

type credentialsRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	username, authenticated := s.deps.Auth.Authenticate(s.deps.Cookies.Token(r))
	writeJSON(w, http.StatusOK, sessionResponse{
		SetupRequired: s.deps.Auth.SetupRequired(),
		Authenticated: authenticated,
		Username:      username,
	})
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	var body credentialsRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	if err := s.deps.Auth.Setup(body.Username, body.Password); err != nil {
		writeError(w, r, err)
		return
	}
	writeNoContent(w)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var body credentialsRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	token, err := s.deps.Auth.Login(body.Username, body.Password, clientIP(r))
	if err != nil {
		writeError(w, r, err)
		return
	}
	s.deps.Cookies.Set(w, token)
	writeNoContent(w)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.deps.Auth.Logout(s.deps.Cookies.Token(r))
	s.deps.Cookies.Clear(w)
	writeNoContent(w)
}
