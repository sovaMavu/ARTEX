package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// authModeFromEnv reads process env, so every test pins both vars with t.Setenv.

func TestAuthModeDefaultsToOpen(t *testing.T) {
	t.Setenv("ARTEX_REQUIRE_AUTH", "")
	t.Setenv("ARTEX_NOAUTH_CIDRS", "")
	m := authModeFromEnv()
	if m.require {
		t.Fatal("login must be off when ARTEX_REQUIRE_AUTH is unset")
	}
	if !m.allowsPeer("127.0.0.1:54321") || !m.allowsPeer("[::1]:54321") {
		t.Fatal("loopback peers must be inside the default circle")
	}
	if m.allowsPeer("192.168.1.10:80") || m.allowsPeer("203.0.113.9:80") {
		t.Fatal("non-loopback peers must not be inside the default circle")
	}
	if m.allowsPeer("garbage") {
		t.Fatal("an unparseable peer must be refused")
	}
}

func TestAuthModeRequireFlag(t *testing.T) {
	for _, v := range []string{"1", "true", "on", "YES"} {
		t.Setenv("ARTEX_REQUIRE_AUTH", v)
		if !authModeFromEnv().require {
			t.Fatalf("ARTEX_REQUIRE_AUTH=%q must enable password login", v)
		}
	}
	for _, v := range []string{"", "0", "false", "no"} {
		t.Setenv("ARTEX_REQUIRE_AUTH", v)
		if authModeFromEnv().require {
			t.Fatalf("ARTEX_REQUIRE_AUTH=%q must leave login off", v)
		}
	}
}

func TestAuthModeCustomCIDRs(t *testing.T) {
	t.Setenv("ARTEX_REQUIRE_AUTH", "")
	t.Setenv("ARTEX_NOAUTH_CIDRS", "172.17.0.0/16, not-a-cidr ,10.0.0.5")
	m := authModeFromEnv()
	if !m.allowsPeer("172.17.0.3:5000") {
		t.Fatal("explicit CIDR peer must be allowed")
	}
	if !m.allowsPeer("10.0.0.5:5000") {
		t.Fatal("a bare IP must mean that single host, not be dropped")
	}
	if m.allowsPeer("10.0.0.6:5000") {
		t.Fatal("a bare IP must not widen to its /24")
	}
	// Setting the variable replaces the default loopback circle rather than adding
	// to it, so IPv6 loopback is now outside — assert the documented semantics.
	if m.allowsPeer("[::1]:5000") {
		t.Fatal("an explicit ARTEX_NOAUTH_CIDRS replaces the default loopback set")
	}
	if m.allowsPeer("127.0.0.1:5000") {
		t.Fatal("setting ARTEX_NOAUTH_CIDRS replaces the default loopback set, it does not extend it")
	}
	if len(m.circle) != 2 {
		t.Fatalf("malformed entries must be dropped, got %d networks", len(m.circle))
	}
}

func openServer() *Server {
	return &Server{auth: authMode{circle: defaultNoAuthCIDRs()}}
}

// next records whether it ran, so a rejected request can be told from a handled one.
func next() (http.Handler, *bool) {
	ran := false
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
		w.WriteHeader(200)
	}), &ran
}

func TestRequireAuthOpenForLoopback(t *testing.T) {
	s := openServer()
	h, ran := next()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/tasks", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	s.requireAuth(h).ServeHTTP(w, r)
	if !*ran || w.Code != 200 {
		t.Fatalf("loopback request must pass without a token: ran=%v code=%d body=%s", *ran, w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-ARTEX-Mode"); got != "noauth" {
		t.Fatalf("X-ARTEX-Mode=%q want noauth", got)
	}
}

// The docker-compose topology: the browser reaches the host's published port, so
// the container sees the userland proxy's private address, not 127.0.0.1. That must
// work for the operator's loopback browser and must NOT work for a remote one.
func TestRequireAuthDockerProxyTopology(t *testing.T) {
	s := openServer() // default circle: loopback only
	cases := []struct {
		name   string
		peer   string
		host   string
		expect bool
	}{
		{"desktop host-gateway peer, loopback Host", "192.168.65.1:41000", "127.0.0.1:8787", true},
		{"docker bridge peer, localhost Host", "172.17.0.1:41000", "localhost:8787", true},
		{"docker bridge peer, bare host name", "172.17.0.1:41000", "artex-host:8787", true},
		{"docker bridge peer, LAN browser Host", "172.17.0.1:41000", "192.168.1.50:8787", false},
		{"docker bridge peer, public Host", "172.17.0.1:41000", "pentest.example.com", false},
		{"public peer, loopback Host", "203.0.113.9:41000", "127.0.0.1:8787", false},
		{"unparseable peer", "garbage", "127.0.0.1:8787", false},
		{"empty Host", "172.17.0.1:41000", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, ran := next()
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/api/tasks", nil)
			r.RemoteAddr = c.peer
			if c.host != "" {
				r.Host = c.host
			}
			s.requireAuth(h).ServeHTTP(w, r)
			if *ran != c.expect {
				t.Fatalf("peer=%q host=%q allowed=%v want %v (code %d)", c.peer, c.host, *ran, c.expect, w.Code)
			}
		})
	}
}

func TestRequireAuthRejectsPublicPeer(t *testing.T) {	s := openServer()
	h, ran := next()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/tasks", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	s.requireAuth(h).ServeHTTP(w, r)
	if *ran {
		t.Fatal("a non-loopback peer must never reach the API while login is off")
	}
	if w.Code != 401 {
		t.Fatalf("code=%d want 401", w.Code)
	}
}

func TestRequireAuthCSRFOriginMismatch(t *testing.T) {
	s := openServer()
	h, ran := next()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/tools/custom", strings.NewReader("{}"))
	r.RemoteAddr = "127.0.0.1:5555"
	r.Host = "127.0.0.1:8787"
	r.Header.Set("Origin", "https://evil.test")
	s.requireAuth(h).ServeHTTP(w, r)
	if *ran {
		t.Fatal("a cross-origin write must be rejected: the API can register shell tools")
	}
	if w.Code != 403 {
		t.Fatalf("code=%d want 403", w.Code)
	}

	// Same-origin write and a non-browser write (no Origin) stay allowed.
	for _, origin := range []struct{ host, header string }{
		{"127.0.0.1:8787", "http://127.0.0.1:8787"},
		{"127.0.0.1:8787", ""},
	} {
		h, ran := next()
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/tasks", strings.NewReader("{}"))
		r.RemoteAddr = "127.0.0.1:5555"
		r.Host = origin.host
		if origin.header != "" {
			r.Header.Set("Origin", origin.header)
		}
		s.requireAuth(h).ServeHTTP(w, r)
		if !*ran {
			t.Fatalf("origin %q must be allowed", origin.header)
		}
	}
}

func TestRequireAuthReadNeverNeedsOrigin(t *testing.T) {
	// GET is safe: cross-origin reads are already blocked by CORS, and the UI's
	// EventSource streams carry no Origin on some browsers.
	s := openServer()
	h, ran := next()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/exploration/activity/stream", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("Origin", "https://evil.test")
	s.requireAuth(h).ServeHTTP(w, r)
	if !*ran {
		t.Fatal("reads must not be origin-gated")
	}
}

func TestRequireAuthEnvRestoresLogin(t *testing.T) {
	s := &Server{auth: authMode{require: true}, jwtKey: []byte("0123456789abcdef0123456789abcdef")}
	h, ran := next()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/tasks", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	s.requireAuth(h).ServeHTTP(w, r)
	if *ran {
		t.Fatal("ARTEX_REQUIRE_AUTH=1 must demand a token even from loopback")
	}
	if w.Code != 401 {
		t.Fatalf("code=%d want 401", w.Code)
	}
	if got := w.Header().Get("X-ARTEX-Mode"); got != "auth" {
		t.Fatalf("X-ARTEX-Mode=%q want auth", got)
	}

	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	h, ran = next()
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/api/tasks", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("Authorization", "Bearer "+tok)
	s.requireAuth(h).ServeHTTP(w, r)
	if !*ran || w.Code != 200 {
		t.Fatalf("a valid token must pass: ran=%v code=%d", *ran, w.Code)
	}
}

func TestRequireAuthHealthAlwaysOpen(t *testing.T) {
	for _, mode := range []authMode{{require: true}, {circle: defaultNoAuthCIDRs()}} {
		s := &Server{auth: mode}
		h, ran := next()
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/health", nil)
		r.RemoteAddr = "203.0.113.9:5555"
		s.requireAuth(h).ServeHTTP(w, r)
		if !*ran || w.Code != 200 {
			t.Fatalf("health must be exempt in every mode: ran=%v code=%d", *ran, w.Code)
		}
	}
}

func TestVerifyJWTFailsClosedWithoutKey(t *testing.T) {
	// Open-mode deployments may have no key on disk; validation must not panic or
	// accept a token forged against an empty key.
	tok, err := signJWT([]byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if verifyJWT(tok, nil) {
		t.Fatal("a nil key must never validate a token")
	}
}

func TestLoadOrCreateJWTKeyReadOnlyWritesNothing(t *testing.T) {
	root := t.TempDir()
	keyDir := filepath.Join(root, "missing-keys")
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	key, err := loadOrCreateJWTKey(keyDir, dataDir, true)
	if err != nil {
		t.Fatalf("read-only load must not fail on a missing directory: %v", err)
	}
	if key != nil {
		t.Fatalf("read-only load returned %q; want nil (no key on disk)", key)
	}
	if _, err := os.Stat(keyDir); !os.IsNotExist(err) {
		t.Fatal("read-only load must not create the key directory")
	}

	// An existing key is still returned in read-only mode.
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const existing = "existing-key-0123456789abcdefghij" // loadOrCreateJWTKey wants >= 32 bytes
	if err := os.WriteFile(filepath.Join(keyDir, jwtKeyFilename), []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err = loadOrCreateJWTKey(keyDir, dataDir, true)
	if err != nil || string(key) != existing {
		t.Fatalf("read-only load of an existing key: key=%q err=%v", key, err)
	}
}

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		origin, host string
		want         bool
	}{
		{"", "127.0.0.1:8787", true},
		{"http://127.0.0.1:8787", "127.0.0.1:8787", true},
		{"http://LOCALHOST:8787", "localhost:8787", true},
		{"https://evil.test", "127.0.0.1:8787", false},
		{"null", "127.0.0.1:8787", false},
		{"::not-a-url", "127.0.0.1:8787", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/api/tasks", nil)
		r.Host = c.host
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		if got := sameOrigin(r); got != c.want {
			t.Fatalf("sameOrigin(origin=%q host=%q)=%v want %v", c.origin, c.host, got, c.want)
		}
	}
}
