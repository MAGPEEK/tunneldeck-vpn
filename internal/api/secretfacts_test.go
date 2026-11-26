package api

import (
	"fmt"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

const longPSK = "a-long-enough-pre-shared-key"

var shortSecretAdvice = []vpn.Advisory{{Code: "short_secret", Severity: vpn.AdvisoryWarning, Field: "psk"}}

// keySettingsAdvice is what fakeKeyDriver advises on any settings.
var keySettingsAdvice = []vpn.Advisory{{Code: "test_advice", Severity: vpn.AdvisoryInfo, Field: "host"}}

// newSecretFactsEnv registers the drivers that judge and derive from
// secrets.
func newSecretFactsEnv(t *testing.T) *testEnv {
	t.Helper()
	env := newTestEnv(t)
	if err := env.drivers.Register(keyProtocol, func() vpn.Driver { return fakeKeyDriver{} }); err != nil {
		t.Fatal(err)
	}
	if err := env.drivers.Register(secretAdviceProtocol, func() vpn.Driver { return fakeSecretAdviser{} }); err != nil {
		t.Fatal(err)
	}
	return env
}

type factsJSON struct {
	Advisories []vpn.Advisory    `json:"advisories"`
	Derived    map[string]string `json:"derived"`
}

func (e *testEnv) facts(t *testing.T, method, path, body string) factsJSON {
	t.Helper()
	rec := e.do(t, method, path, body)
	if rec.Code >= 300 {
		t.Fatalf("%s %s = %d: %s", method, path, rec.Code, rec.Body.String())
	}
	assertNoSecret(t, path, rec.Body.String())
	return decode[factsJSON](t, rec)
}

func TestSecretFactsAreComputedOncePerProfile(t *testing.T) {
	env := newSecretFactsEnv(t)
	keyed := env.profiles.add(domain.Profile{Name: "Keyed", Protocol: keyProtocol, Secrets: map[string]string{"privateKey": testSecret}})
	advised := env.profiles.add(domain.Profile{Name: "Advised", Protocol: secretAdviceProtocol, Secrets: map[string]string{"psk": "short"}})
	plain := env.storedProfile("Plain")
	env.connection.setStatus(vpn.Status{State: domain.StateConnected, ProfileID: advised.ID})

	for range 3 {
		assertStatus(t, env.do(t, http.MethodGet, "/api/profiles", ""), http.StatusOK)
		for _, id := range []string{keyed.ID, advised.ID, plain.ID} {
			assertStatus(t, env.do(t, http.MethodGet, "/api/profiles/"+id, ""), http.StatusOK)
		}
		if got := env.facts(t, http.MethodGet, "/api/connection", ""); !reflect.DeepEqual(got.Advisories, shortSecretAdvice) {
			t.Errorf("connection advisories = %+v", got.Advisories)
		}
	}
	if got := env.profiles.secretReadCount(); got != 2 {
		t.Errorf("secrets read %d times, want once per profile whose driver uses them (2)", got)
	}
}

func TestSecretFactsFollowChanges(t *testing.T) {
	env := newSecretFactsEnv(t)
	advised := env.profiles.add(domain.Profile{Name: "Advised", Protocol: secretAdviceProtocol, Secrets: map[string]string{"psk": "short"}})
	keyed := env.profiles.add(domain.Profile{Name: "Keyed", Protocol: keyProtocol, Secrets: map[string]string{"privateKey": testSecret}})
	env.connection.setStatus(vpn.Status{State: domain.StateConnected, ProfileID: advised.ID})
	advisedPath, keyedPath := "/api/profiles/"+advised.ID, "/api/profiles/"+keyed.ID
	connection := func() []vpn.Advisory { return env.facts(t, http.MethodGet, "/api/connection", "").Advisories }

	steps := []struct {
		name      string
		change    func() factsJSON
		path      string
		want      []vpn.Advisory
		wantKey   string
		checkConn bool
	}{
		{
			name: "secret replaced",
			change: func() factsJSON {
				return env.facts(t, http.MethodPut, advisedPath, `{"name":"Advised","secrets":{"psk":"`+longPSK+`"}}`)
			},
			path: advisedPath, want: []vpn.Advisory{}, checkConn: true,
		},
		{
			name: "secret cleared",
			change: func() factsJSON {
				return env.facts(t, http.MethodPut, advisedPath, `{"name":"Advised","clearSecrets":["psk"]}`)
			},
			path: advisedPath, want: shortSecretAdvice, checkConn: true,
		},
		{
			name: "changed past the API with a new revision",
			change: func() factsJSON {
				env.profiles.replace(domain.Profile{
					ID: advised.ID, Name: "Advised", Protocol: secretAdviceProtocol,
					Secrets: map[string]string{"psk": longPSK}, UpdatedAt: time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC),
				})
				return env.facts(t, http.MethodGet, advisedPath, "")
			},
			path: advisedPath, want: []vpn.Advisory{}, checkConn: true,
		},
		{
			name:   "derived key kept",
			change: func() factsJSON { return env.facts(t, http.MethodPut, keyedPath, `{"name":"Keyed"}`) },
			path:   keyedPath, want: keySettingsAdvice, wantKey: "derived-public",
		},
		{
			name: "derived key gone with its secret",
			change: func() factsJSON {
				return env.facts(t, http.MethodPut, keyedPath, `{"name":"Keyed","clearSecrets":["privateKey"]}`)
			},
			path: keyedPath, want: keySettingsAdvice,
		},
	}
	for _, step := range steps {
		changed := step.change()
		read := env.facts(t, http.MethodGet, step.path, "")
		for _, got := range []factsJSON{changed, read} {
			if !reflect.DeepEqual(got.Advisories, step.want) || got.Derived["publicKey"] != step.wantKey {
				t.Errorf("%s: facts = %+v, want advisories %+v and key %q", step.name, got, step.want, step.wantKey)
			}
		}
		if got := connection(); step.checkConn && !reflect.DeepEqual(got, step.want) {
			t.Errorf("%s: connection advisories = %+v, want %+v", step.name, got, step.want)
		}
	}
}

func TestSecretFactsOfADeletedProfileAreDropped(t *testing.T) {
	env := newSecretFactsEnv(t)
	advised := env.profiles.add(domain.Profile{Name: "Advised", Protocol: secretAdviceProtocol, Secrets: map[string]string{"psk": "short"}})
	env.facts(t, http.MethodGet, "/api/profiles/"+advised.ID, "")

	assertStatus(t, env.do(t, http.MethodDelete, "/api/profiles/"+advised.ID, ""), http.StatusNoContent)

	if _, _, ok := env.server.facts.lookup(advised.ID, advised.UpdatedAt); ok {
		t.Error("the facts of the deleted profile are still cached")
	}
}

func TestSecretFactsCache(t *testing.T) {
	revision := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	facts := secretFacts{advisories: shortSecretAdvice, derived: map[string]string{"publicKey": "pub"}}
	tests := []struct {
		name      string
		act       func(c *secretFactsCache)
		revision  time.Time
		wantFound bool
	}{
		{
			name: "stored entry matches its revision",
			act: func(c *secretFactsCache) {
				_, generation, _ := c.lookup("p1", revision)
				c.store("p1", revision, facts, generation)
			},
			revision: revision, wantFound: true,
		},
		{
			name: "another revision misses",
			act: func(c *secretFactsCache) {
				_, generation, _ := c.lookup("p1", revision)
				c.store("p1", revision, facts, generation)
			},
			revision: revision.Add(time.Nanosecond),
		},
		{
			name: "invalidated entry misses",
			act: func(c *secretFactsCache) {
				_, generation, _ := c.lookup("p1", revision)
				c.store("p1", revision, facts, generation)
				c.invalidate("p1")
			},
			revision: revision,
		},
		{
			name: "a computation that began before an invalidation is not stored",
			act: func(c *secretFactsCache) {
				_, generation, _ := c.lookup("p1", revision)
				c.invalidate("p1")
				c.store("p1", revision, facts, generation)
			},
			revision: revision,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newSecretFactsCache()
			tt.act(c)
			got, _, found := c.lookup("p1", tt.revision)
			if found != tt.wantFound {
				t.Fatalf("found = %v, want %v", found, tt.wantFound)
			}
			if found && !reflect.DeepEqual(got, facts) {
				t.Errorf("facts = %+v, want %+v", got, facts)
			}
		})
	}
}

func TestSecretFactsCacheHandsOutCopies(t *testing.T) {
	c := newSecretFactsCache()
	stored := secretFacts{advisories: []vpn.Advisory{{Code: "a"}}, derived: map[string]string{"publicKey": "pub"}}
	_, generation, _ := c.lookup("p1", time.Time{})
	c.store("p1", time.Time{}, stored, generation)
	stored.advisories[0].Code = "changed"

	got, _, _ := c.lookup("p1", time.Time{})
	got.derived["publicKey"] = "changed"

	again, _, _ := c.lookup("p1", time.Time{})
	if again.advisories[0].Code != "a" || again.derived["publicKey"] != "pub" {
		t.Errorf("cached facts were changed through a copy: %+v", again)
	}
}

func TestSecretFactsUnderConcurrentUpdates(t *testing.T) {
	env := newSecretFactsEnv(t)
	advised := env.profiles.add(domain.Profile{Name: "Advised", Protocol: secretAdviceProtocol, Secrets: map[string]string{"psk": "short"}})
	path := "/api/profiles/" + advised.ID

	expectOK := func(method, body string) {
		if rec := env.do(t, method, path, body); rec.Code != http.StatusOK {
			t.Errorf("%s %s = %d: %s", method, path, rec.Code, rec.Body.String())
		}
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for range 20 {
				expectOK(http.MethodGet, "")
			}
		})
		wg.Go(func() {
			expectOK(http.MethodPut, fmt.Sprintf(`{"name":"Advised","secrets":{"psk":"short-%d"}}`, i))
		})
	}
	wg.Wait()
	env.facts(t, http.MethodPut, path, `{"name":"Advised","secrets":{"psk":"`+longPSK+`"}}`)

	if got := env.facts(t, http.MethodGet, path, "").Advisories; len(got) != 0 {
		t.Errorf("advisories after the last update = %+v, want none", got)
	}
}
