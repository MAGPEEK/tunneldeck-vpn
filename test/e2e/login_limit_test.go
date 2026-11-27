//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

// remoteLoginSources are addresses on the server's loopback, outside the
// VPN pool like probeSource, that each make one failed login on the remote
// listener; one more than the failures that lock it.
const remoteLoginSources = 11

// wrongLogin is the body of every login attempt of the rate-limit check.
const wrongLogin = `{"username":"admin","password":"wrong-password"}`

// loginAnswer is the response to a login attempt made with curl.
type loginAnswer struct {
	status     int
	retryAfter int
	code       string
}

// checksLoginLimits: the login rate limits depend neither on the VPN
// variant nor on the iptables backend, so only the first scenario checks
// them.
func (sc *scenario) checksLoginLimits() bool {
	return sc.variant.name == variants[0].name && sc.td.backend.name == backends[0].name
}

// checkLoginLimits checks the login rate limits of SPEC §8 and §8.1 while
// remote access is on: ten clients failing on the remote listener lock it
// for everyone, while a client on the LAN listener still gets its own
// growing cooldown, 10 s and then 20 s.
func (sc *scenario) checkLoginLimits(t *testing.T, vpnIP netip.Addr) {
	t.Helper()
	sources := sc.addRemoteLoginSources(t)
	remoteURL := fmt.Sprintf("https://%s:%d/api/login", vpnIP, remoteAccessPort)
	for i, source := range sources[:remoteLoginSources-1] {
		wantRetry := 10
		if i == remoteLoginSources-2 {
			wantRetry = 60
		}
		sc.expectLogin(t, remoteURL, source, loginAnswer{status: 401, retryAfter: wantRetry, code: "invalid_credentials"})
	}
	locked := sc.tryLogin(t, remoteURL, sources[remoteLoginSources-1])
	if locked.status != 429 || locked.code != "rate_limited_remote" || locked.retryAfter < 50 || locked.retryAfter > 60 {
		t.Errorf("login on the locked remote listener = %+v, want 429 rate_limited_remote with Retry-After 50–60", locked)
	}

	lanURL := fmt.Sprintf("http://%s:%d/api/login", sc.td.hostAddress(t), uiPort)
	for _, cooldown := range []int{10, 20} {
		sc.expectLogin(t, lanURL, "", loginAnswer{status: 401, retryAfter: cooldown, code: "invalid_credentials"})
		failedAt := time.Now()
		rejected := sc.tryLogin(t, lanURL, "")
		if rejected.status != 429 || rejected.code != "rate_limited" || rejected.retryAfter < 1 || rejected.retryAfter > cooldown {
			t.Errorf("LAN login during the cooldown = %+v, want 429 rate_limited with Retry-After 1–%d", rejected, cooldown)
		}
		if cooldown == 10 {
			time.Sleep(time.Until(failedAt.Add(time.Duration(cooldown)*time.Second + 500*time.Millisecond)))
		}
	}
}

// addRemoteLoginSources adds the remote login source addresses to the
// server's loopback and removes them when the test ends.
func (sc *scenario) addRemoteLoginSources(t *testing.T) []string {
	t.Helper()
	sources := make([]string, remoteLoginSources)
	for i := range sources {
		sources[i] = fmt.Sprintf("198.18.1.%d", i+1)
		sc.stack.exec(t, sc.variant.service, "ip", "addr", "replace", sources[i]+"/32", "dev", "lo")
		t.Cleanup(func() {
			_, _ = sc.stack.tryExec(sc.variant.service, "ip", "addr", "del", sources[i]+"/32", "dev", "lo")
		})
	}
	return sources
}

func (sc *scenario) expectLogin(t *testing.T, url, source string, want loginAnswer) {
	t.Helper()
	if got := sc.tryLogin(t, url, source); got != want {
		t.Errorf("login at %s from %q = %+v, want %+v", url, source, got, want)
	}
}

// tryLogin posts wrong credentials to url from the server container, from
// source when it is set, and returns status, Retry-After and problem code.
func (sc *scenario) tryLogin(t *testing.T, url, source string) loginAnswer {
	t.Helper()
	args := []string{"curl", "--insecure", "--silent", "--show-error", "--max-time", "10", "--dump-header", "-",
		"--header", "Content-Type: application/json", "--header", "X-TunnelDeck-Request: 1", "--data", wrongLogin}
	if source != "" {
		args = append(args, "--interface", source)
	}
	out := sc.stack.exec(t, sc.variant.service, append(args, url)...)
	head, body, _ := strings.Cut(strings.ReplaceAll(out, "\r\n", "\n"), "\n\n")
	var answer loginAnswer
	if fields := strings.Fields(firstLine(head)); len(fields) > 1 {
		answer.status, _ = strconv.Atoi(fields[1])
	}
	for _, line := range strings.Split(head, "\n") {
		if name, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(name, "Retry-After") {
			answer.retryAfter, _ = strconv.Atoi(strings.TrimSpace(value))
		}
	}
	var problem struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(body), &problem); err != nil {
		t.Errorf("login at %s: undecodable body %q: %v", url, body, err)
	}
	answer.code = problem.Code
	return answer
}
