package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func testScopePayload() map[string]any {
	return map[string]any{
		"schema":        "artex.scope.v1",
		"task_id":       42,
		"company_id":    7,
		"engagement":    "acme-q4",
		"domains":       []string{"example.com", "*.example.com"},
		"ips":           []string{"203.0.113.10"},
		"cidrs":         []string{"10.10.0.0/16"},
		"excludes":      []string{"10.10.5.0/24", "admin.example.com"},
		"exclude_ports": []int{22, 3389},
		"policy": map[string]any{
			"max_rate":        500,
			"max_hosts":       4096,
			"allow_syn":       false,
			"allow_os_detect": false,
			"allow_axfr":      false,
		},
		"issued_at":  "2026-11-09T10:00:00Z",
		"expires_at": "2026-12-09T10:00:00Z",
		"nonce":      "b3f0c1d2e4a5968778695a4b3c2d1e0f",
	}
}

// TestScopeSignatureCrossLanguage pins the exact bytes and HMAC the Python
// runner expects. If this test changes, the runner will reject every scope.
func TestScopeSignatureCrossLanguage(t *testing.T) {
	payload := testScopePayload()
	canonical, err := canonicalScopeJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	wantCanonical := `{"cidrs":["10.10.0.0/16"],"company_id":7,"domains":["example.com","*.example.com"],"engagement":"acme-q4","exclude_ports":[22,3389],"excludes":["10.10.5.0/24","admin.example.com"],"expires_at":"2026-12-09T10:00:00Z","ips":["203.0.113.10"],"issued_at":"2026-11-09T10:00:00Z","nonce":"b3f0c1d2e4a5968778695a4b3c2d1e0f","policy":{"allow_axfr":false,"allow_os_detect":false,"allow_syn":false,"max_hosts":4096,"max_rate":500},"schema":"artex.scope.v1","task_id":42}`
	if string(canonical) != wantCanonical {
		t.Fatalf("canonical mismatch:\n got %s\nwant %s", canonical, wantCanonical)
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	sig, err := signScopePayload(payload, key)
	if err != nil {
		t.Fatal(err)
	}
	wantSig := "hmac-sha256:87327332c3d4c8ba41b92d88b4e0376e924cdccd6e05568ad854628c0675be3b"
	if sig != wantSig {
		t.Fatalf("signature=%s, want %s", sig, wantSig)
	}
	payload["signature"] = sig
	if !verifyScopeSignature(payload, key) {
		t.Fatal("signature did not verify")
	}
	payload["task_id"] = 43
	if verifyScopeSignature(payload, key) {
		t.Fatal("tampered payload verified")
	}
}

func TestScopePayloadMergesExclusions(t *testing.T) {
	e := &ScopeExporter{Policy: ScopePolicy{MaxRate: 500, MaxHosts: 4096}}
	snap := db.ScopeSnapshot{
		TaskID:  42,
		Domains: []string{"example.com", "*.example.com", "example.com"},
		IPs:     []string{"203.0.113.10"},
		CIDRs:   []string{"10.10.0.0/16"},
	}
	issued := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	payload, err := e.buildPayload(snap, scopeExclusions{
		Domains: []string{"Admin.Example.com.", "admin.example.com"},
		IPs:     []string{"10.10.0.9"},
		CIDRs:   []string{"10.10.5.0/24"},
		Ports:   []int{3389, 22, 22},
	}, issued, issued.Add(720*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got := payload["task_id"]; got != int64(42) {
		t.Fatalf("task_id=%v", got)
	}
	if got := payload["engagement"]; got != "task-42" {
		t.Fatalf("engagement=%v", got)
	}
	domains := payload["domains"].([]string)
	if len(domains) != 2 || domains[0] != "*.example.com" || domains[1] != "example.com" {
		t.Fatalf("domains=%v", domains)
	}
	excludes := payload["excludes"].([]string)
	wantExcludes := []string{"10.10.0.9", "10.10.5.0/24", "admin.example.com"}
	if len(excludes) != len(wantExcludes) {
		t.Fatalf("excludes=%v, want %v", excludes, wantExcludes)
	}
	for i := range wantExcludes {
		if excludes[i] != wantExcludes[i] {
			t.Fatalf("excludes=%v, want %v", excludes, wantExcludes)
		}
	}
	ports := payload["exclude_ports"].([]int)
	if len(ports) != 2 || ports[0] != 22 || ports[1] != 3389 {
		t.Fatalf("ports=%v", ports)
	}
	policy := payload["policy"].(map[string]any)
	if policy["max_rate"] != 500 || policy["max_hosts"] != 4096 {
		t.Fatalf("policy=%v", policy)
	}
}

func TestScopeFileWriteAndPreserve(t *testing.T) {
	dir := t.TempDir()
	e := &ScopeExporter{
		Dir:    dir,
		Key:    make([]byte, 32),
		TTL:    720 * time.Hour,
		Policy: ScopePolicy{MaxRate: 500, MaxHosts: 4096},
	}
	snap := db.ScopeSnapshot{TaskID: 7, Domains: []string{"example.com", "*.example.com"}}
	now := time.Now().UTC().Truncate(time.Second)
	payload, err := e.buildPayload(snap, scopeExclusions{}, now, now.Add(e.TTL))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signScopePayload(payload, e.Key)
	if err != nil {
		t.Fatal(err)
	}
	payload["signature"] = sig
	path := filepath.Join(dir, "7.json")
	if err := writeScopeFile(path, payload); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk map[string]any
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatal(err)
	}
	if !verifyScopeSignature(onDisk, e.Key) {
		t.Fatal("written file does not verify")
	}

	// Same authorization, different nonce/time: preserve.
	next, err := e.buildPayload(snap, scopeExclusions{}, now.Add(time.Minute), now.Add(e.TTL))
	if err != nil {
		t.Fatal(err)
	}
	preserved, err := e.preserveExisting(path, next, now)
	if err != nil {
		t.Fatal(err)
	}
	if !preserved {
		t.Fatal("unchanged authorization should preserve the existing file")
	}

	// Changed authorization: rewrite.
	changed := db.ScopeSnapshot{TaskID: 7, Domains: []string{"example.com", "*.example.com", "api.example.com"}}
	next, err = e.buildPayload(changed, scopeExclusions{}, now.Add(time.Minute), now.Add(e.TTL))
	if err != nil {
		t.Fatal(err)
	}
	preserved, err = e.preserveExisting(path, next, now)
	if err != nil {
		t.Fatal(err)
	}
	if preserved {
		t.Fatal("changed authorization must not preserve")
	}

	// Expiry inside the refresh window: rewrite.
	short, err := e.buildPayload(snap, scopeExclusions{}, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	shortSig, err := signScopePayload(short, e.Key)
	if err != nil {
		t.Fatal(err)
	}
	short["signature"] = shortSig
	shortPath := filepath.Join(dir, "short.json")
	if err := writeScopeFile(shortPath, short); err != nil {
		t.Fatal(err)
	}
	preserved, err = e.preserveExisting(shortPath, payload, now)
	if err != nil {
		t.Fatal(err)
	}
	if preserved {
		t.Fatal("expiring file must be refreshed")
	}

	// Tampered signature: rewrite.
	onDisk["task_id"] = 8
	tampered, _ := json.Marshal(onDisk)
	if err := os.WriteFile(path, tampered, 0o640); err != nil {
		t.Fatal(err)
	}
	preserved, err = e.preserveExisting(path, payload, now)
	if err != nil {
		t.Fatal(err)
	}
	if preserved {
		t.Fatal("tampered file must be rewritten")
	}
}

func TestReadScopeExclusions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "7.exclude.json")
	body := `{"domains":["Admin.Example.com.","admin.example.com"],"ips":["10.10.0.9","bad"],"cidrs":["10.10.5.1/24","bad"],"ports":[3389,22,0,70000,22]}`
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	excl, err := readScopeExclusions(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(excl.Domains) != 1 || excl.Domains[0] != "admin.example.com" {
		t.Fatalf("domains=%v", excl.Domains)
	}
	if len(excl.IPs) != 1 || excl.IPs[0] != "10.10.0.9" {
		t.Fatalf("ips=%v", excl.IPs)
	}
	if len(excl.CIDRs) != 1 || excl.CIDRs[0] != "10.10.5.0/24" {
		t.Fatalf("cidrs=%v", excl.CIDRs)
	}
	if len(excl.Ports) != 2 || excl.Ports[0] != 22 || excl.Ports[1] != 3389 {
		t.Fatalf("ports=%v", excl.Ports)
	}

	missing, err := readScopeExclusions(filepath.Join(dir, "missing.json"))
	if err != nil || len(missing.Domains) != 0 {
		t.Fatalf("missing file: %+v err=%v", missing, err)
	}
}

func TestNewScopeExporterFromEnv(t *testing.T) {
	t.Setenv("ARTEX_SCOPE_KEY", "")
	exp, err := NewScopeExporterFromEnv(t.TempDir(), nil)
	if err != nil || exp != nil {
		t.Fatalf("unset key: exp=%v err=%v", exp, err)
	}

	dir := t.TempDir()
	t.Setenv("ARTEX_SCOPE_KEY", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
	t.Setenv("ARTEX_SCOPE_DIR", dir)
	t.Setenv("ARTEX_SCOPE_TTL", "24h")
	t.Setenv("ARTEX_SCOPE_POLICY_MAX_RATE", "100")
	t.Setenv("ARTEX_SCOPE_POLICY_MAX_HOSTS", "64")
	t.Setenv("ARTEX_SCOPE_ALLOW_SYN", "true")
	exp, err = NewScopeExporterFromEnv(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if exp == nil || exp.Dir != dir || exp.TTL != 24*time.Hour {
		t.Fatalf("exporter=%+v", exp)
	}
	if exp.Policy.MaxRate != 100 || exp.Policy.MaxHosts != 64 || !exp.Policy.AllowSYN || exp.Policy.AllowOSDetect {
		t.Fatalf("policy=%+v", exp.Policy)
	}

	t.Setenv("ARTEX_SCOPE_KEY", "not-base64")
	if _, err := NewScopeExporterFromEnv(t.TempDir(), nil); err == nil {
		t.Fatal("invalid key must fail")
	}
	t.Setenv("ARTEX_SCOPE_KEY", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
	t.Setenv("ARTEX_SCOPE_TTL", "nope")
	if _, err := NewScopeExporterFromEnv(t.TempDir(), nil); err == nil {
		t.Fatal("invalid TTL must fail")
	}
}
