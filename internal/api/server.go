package api

import (
	"net/http"
	"sync"
	"time"
)

// defaultHeartbeat is the interval of the SSE keep-alive comment.
const defaultHeartbeat = 20 * time.Second

// Deps are the services the API uses. All are required.
type Deps struct {
	Auth          Auth
	Cookies       SessionCookies
	Profiles      Profiles
	Drivers       Drivers
	Importer      Importer
	Connection    Connection
	FirewallStore FirewallStore
	Firewall      Firewall
	System        System

	RemoteAccess         RemoteAccessSettings
	RemoteAccessListener RemoteAccessListener
}

// Options tune the API; zero values select the defaults.
type Options struct {
	// Now defaults to time.Now.
	Now func() time.Time
	// Heartbeat is the SSE keep-alive interval, 20 s by default.
	Heartbeat time.Duration
}

// Server serves /api/* on both listeners; wrap the handler of the HTTPS
// listener with SecureListener so cookies get Secure and HSTS is sent.
type Server struct {
	deps      Deps
	now       func() time.Time
	heartbeat time.Duration
	mux       *http.ServeMux
	handler   http.Handler

	// portsMu serialises host-access and remote-access updates: their ports
	// are checked against each other, and a rollback never overwrites a
	// newer change.
	portsMu sync.Mutex

	closeOnce sync.Once
	closed    chan struct{} // closed by CloseStreams
}

// New returns the API server.
func New(deps Deps, opts Options) *Server {
	s := &Server{
		deps:      deps,
		now:       opts.Now,
		heartbeat: opts.Heartbeat,
		mux:       http.NewServeMux(),
		closed:    make(chan struct{}),
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.heartbeat <= 0 {
		s.heartbeat = defaultHeartbeat
	}
	s.routes()
	s.handler = logRequests(checkCSRF(s.mux))
	return s
}

// ServeHTTP handles requests below /api/.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// CloseStreams ends every open event stream, so a graceful shutdown does
// not wait for them. Register it with http.Server.RegisterOnShutdown.
func (s *Server) CloseStreams() {
	s.closeOnce.Do(func() { close(s.closed) })
}

func (s *Server) routes() {
	s.public("GET /api/session", s.getSession)
	s.public("POST /api/setup", s.setup)
	s.public("POST /api/login", s.login)
	s.private("POST /api/logout", s.logout)

	s.private("GET /api/drivers", s.listDrivers)
	s.private("GET /api/profiles", s.listProfiles)
	s.private("POST /api/profiles", s.createProfile)
	s.private("POST /api/profiles/import", s.importProfile)
	s.private("GET /api/profiles/{id}", s.getProfile)
	s.private("PUT /api/profiles/{id}", s.updateProfile)
	s.private("DELETE /api/profiles/{id}", s.deleteProfile)

	s.private("GET /api/connection", s.getConnection)
	s.private("POST /api/connection/connect", s.connect)
	s.private("POST /api/connection/disconnect", s.disconnect)
	s.private("POST /api/connection/reconnect", s.reconnect)
	s.private("GET /api/logs", s.getLogs)
	s.private("GET /api/events", s.streamEvents)

	s.private("GET /api/host-access", s.getHostAccess)
	s.private("PUT /api/host-access", s.putHostAccess)
	s.private("GET /api/system", s.getSystem)

	s.private("GET /api/remote-access", s.getRemoteAccess)
	s.private("PUT /api/remote-access", s.putRemoteAccess)
	s.private("POST /api/remote-access/certificate", s.uploadCertificate)

	s.mux.HandleFunc("/api/", s.unmatched)
}

func (s *Server) public(pattern string, handler http.HandlerFunc) {
	s.mux.Handle(pattern, handler)
}

func (s *Server) private(pattern string, handler http.HandlerFunc) {
	s.mux.Handle(pattern, s.requireSession(handler))
}

// probeMethods are tried to tell 405 from 404.
var probeMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete}

// unmatched answers requests no route takes: 405 with Allow when the path
// exists for other methods, 404 otherwise.
func (s *Server) unmatched(w http.ResponseWriter, r *http.Request) {
	var allowed []string
	for _, method := range probeMethods {
		probe := r.Clone(r.Context())
		probe.Method = method
		if _, pattern := s.mux.Handler(probe); pattern != "/api/" && pattern != "" {
			allowed = append(allowed, method)
		}
	}
	if len(allowed) == 0 {
		writeProblem(w, newProblem(http.StatusNotFound, CodeNotFound, "The resource does not exist."))
		return
	}
	for _, method := range allowed {
		w.Header().Add("Allow", method)
	}
	writeProblem(w, newProblem(http.StatusMethodNotAllowed, CodeMethodNotAllowed, "The method is not allowed here."))
}
