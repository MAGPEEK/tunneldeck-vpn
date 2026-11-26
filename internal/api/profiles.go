package api

import (
	"context"
	"errors"
	"maps"
	"net/http"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

// profileView is a profile as the API returns it: secrets reduced to
// hasValue, plus the driver's advisories.
type profileView struct {
	domain.PublicProfile
	Advisories []vpn.Advisory `json:"advisories"`
}

type profileRequest struct {
	Name           string                 `json:"name"`
	Protocol       domain.Protocol        `json:"protocol"`
	Settings       domain.Settings        `json:"settings"`
	Secrets        map[string]string      `json:"secrets"`
	ClearSecrets   []string               `json:"clearSecrets"`
	DailyReconnect *domain.DailyReconnect `json:"dailyReconnect"`
	PublicAddress  string                 `json:"publicAddress"`
}

func (req profileRequest) profile() domain.Profile {
	p := domain.Profile{
		Name:           req.Name,
		Protocol:       req.Protocol,
		Settings:       nonNilMap(req.Settings),
		Secrets:        nonNilMap(req.Secrets),
		DailyReconnect: domain.DefaultDailyReconnect(),
		PublicAddress:  req.PublicAddress,
	}
	if req.DailyReconnect != nil {
		p.DailyReconnect = *req.DailyReconnect
	}
	return p
}

type driverView struct {
	Protocol domain.Protocol `json:"protocol"`
	Schema   vpn.FormSchema  `json:"schema"`
}

type importRequest struct {
	Protocol domain.Protocol `json:"protocol"`
	Text     string          `json:"text"`
}

// importResponse is the only response that carries secret values: those
// found in the uploaded text, sent back to the same client (SPEC §9).
type importResponse struct {
	Settings domain.Settings   `json:"settings"`
	Secrets  map[string]string `json:"secrets"`
	Warnings []ImportWarning   `json:"warnings"`
	Missing  []string          `json:"missing"`
}

// driver returns a fresh, stopped driver for protocol. It is used only to
// describe, validate and advise, never started.
func (s *Server) driver(protocol domain.Protocol) (vpn.Driver, error) {
	factory, err := s.deps.Drivers.Lookup(protocol)
	if err != nil {
		return nil, err
	}
	return factory(), nil
}

func (s *Server) advise(p domain.PublicProfile) []vpn.Advisory {
	d, err := s.driver(p.Protocol)
	if err != nil {
		return []vpn.Advisory{}
	}
	return nonNilSlice(d.Advise(p))
}

func (s *Server) view(p domain.PublicProfile) profileView {
	return profileView{PublicProfile: p, Advisories: s.advise(p)}
}

func (s *Server) listDrivers(w http.ResponseWriter, _ *http.Request) {
	views := []driverView{}
	for _, protocol := range s.deps.Drivers.Protocols() {
		d, err := s.driver(protocol)
		if err != nil {
			continue
		}
		views = append(views, driverView{Protocol: protocol, Schema: d.Describe()})
	}
	writeJSON(w, http.StatusOK, views)
}

func (s *Server) listProfiles(w http.ResponseWriter, _ *http.Request) {
	profiles := s.deps.Profiles.ListProfiles()
	views := make([]profileView, len(profiles))
	for i, p := range profiles {
		views[i] = s.view(p)
	}
	writeJSON(w, http.StatusOK, views)
}

func (s *Server) getProfile(w http.ResponseWriter, r *http.Request) {
	p, err := s.deps.Profiles.GetProfile(r.PathValue("id"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.view(p))
}

func (s *Server) createProfile(w http.ResponseWriter, r *http.Request) {
	var req profileRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	p := req.profile()
	if err := s.validateProfile(p); err != nil {
		writeError(w, r, err)
		return
	}
	created, err := s.deps.Profiles.CreateProfile(p)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, s.view(created))
}

func (s *Server) updateProfile(w http.ResponseWriter, r *http.Request) {
	var req profileRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	id := r.PathValue("id")
	stored, err := s.deps.Profiles.ProfileWithSecrets(id)
	if err != nil {
		writeError(w, r, err)
		return
	}
	p := req.profile()
	p.ID = id
	if p.Protocol == "" {
		p.Protocol = stored.Protocol
	}
	if p.Protocol != stored.Protocol {
		writeError(w, r, domain.NewFieldError("protocol", domain.Issue("protocol_immutable"), "cannot be changed"))
		return
	}
	merged := p
	merged.Secrets = mergeSecrets(stored.Secrets, p.Secrets, req.ClearSecrets)
	if err := s.validateProfile(merged); err != nil {
		writeError(w, r, err)
		return
	}
	updated, err := s.deps.Profiles.UpdateProfile(p, req.ClearSecrets)
	if err != nil {
		writeError(w, r, err)
		return
	}
	s.deps.Connection.ProfileChanged(id)
	writeJSON(w, http.StatusOK, s.view(updated))
}

// mergeSecrets applies an update to the stored secrets the way the store
// does: cleared fields go, non-empty new values replace.
func mergeSecrets(stored, updates map[string]string, cleared []string) map[string]string {
	merged := nonNilMap(maps.Clone(stored))
	for _, field := range cleared {
		delete(merged, field)
	}
	for field, value := range updates {
		if value != "" {
			merged[field] = value
		}
	}
	return merged
}

// validateProfile runs the driver-independent and the driver checks and
// reports all fields together.
func (s *Server) validateProfile(p domain.Profile) error {
	p.Normalize()
	v := &domain.ValidationError{}
	mergeValidation(v, p.Validate())
	if p.Protocol != "" {
		d, err := s.driver(p.Protocol)
		switch {
		case errors.Is(err, domain.ErrNotFound):
			v.AddIssue("protocol", domain.Issue("protocol_unsupported"), "is not supported")
		case err != nil:
			return err
		default:
			mergeValidation(v, d.Validate(p))
		}
	}
	return v.OrNil()
}

func mergeValidation(v *domain.ValidationError, err error) {
	var fields *domain.ValidationError
	if errors.As(err, &fields) {
		v.Merge("", fields)
	}
}

// deleteProfile deletes a profile in any connection state (SPEC §9). The
// active profile is disconnected first, which clears the desired
// connection, and deleted once the tunnel is down.
func (s *Server) deleteProfile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.deps.Connection.Status().ProfileID == id {
		if err := s.disconnectAndWait(r.Context()); err != nil {
			writeError(w, r, err)
			return
		}
	}
	if err := s.deps.Profiles.DeleteProfile(id); err != nil {
		writeError(w, r, err)
		return
	}
	s.deps.Connection.ProfileChanged(id)
	writeNoContent(w)
}

// disconnectAndWait disconnects and waits, at most disconnectTimeout, until
// the manager reports the tunnel disconnected. It subscribes before
// disconnecting so the final state event cannot be missed.
func (s *Server) disconnectAndWait(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s.disconnectTimeout)
	defer cancel()
	events, unsubscribe := s.deps.Connection.Subscribe()
	defer unsubscribe()
	if err := s.deps.Connection.Disconnect(ctx); err != nil {
		return err
	}
	if s.deps.Connection.Status().State == domain.StateDisconnected {
		return nil
	}
	if awaitDisconnected(ctx, events) || s.deps.Connection.Status().State == domain.StateDisconnected {
		return nil
	}
	return unavailableError{detail: "The connection did not stop in time, so the profile was not deleted. Try again."}
}

// awaitDisconnected reads events until a disconnected state arrives (true),
// or the stream closes or ctx ends (false).
func awaitDisconnected(ctx context.Context, events <-chan domain.Event) bool {
	for {
		select {
		case <-ctx.Done():
			return false
		case event, ok := <-events:
			if !ok {
				return false
			}
			if state, isState := event.(domain.StateEvent); isState && state.State == domain.StateDisconnected {
				return true
			}
		}
	}
}

func (s *Server) importProfile(w http.ResponseWriter, r *http.Request) {
	var req importRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	draft, err := s.deps.Importer.Import(req.Protocol, req.Text)
	if errors.Is(err, domain.ErrNotFound) {
		err = domain.NewFieldError("protocol", domain.Issue("protocol_unsupported"), "is not supported")
	}
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, importResponse{
		Settings: nonNilMap(draft.Settings),
		Secrets:  nonNilMap(draft.Secrets),
		Warnings: nonNilSlice(draft.Warnings),
		Missing:  nonNilSlice(draft.Missing),
	})
}

// nonNilMap and nonNilSlice make JSON show {} and [] instead of null.
func nonNilMap[M ~map[K]V, K comparable, V any](m M) M {
	if m == nil {
		return M{}
	}
	return m
}

func nonNilSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
