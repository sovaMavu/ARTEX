package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

const (
	scopeSchema        = "artex.scope.v1"
	scopeSignaturePref = "hmac-sha256:"
	scopeRefreshWindow = 24 * time.Hour
	scopeMaxExclude    = 1 << 20 // 1 MiB operator exclusion file
)

// ScopePolicy is the signed per-task network policy. JSON field order is
// irrelevant because the signer canonicalizes keys, but keep it stable for
// readability.
type ScopePolicy struct {
	MaxRate       int  `json:"max_rate"`
	MaxHosts      int  `json:"max_hosts"`
	AllowSYN      bool `json:"allow_syn"`
	AllowOSDetect bool `json:"allow_os_detect"`
	AllowAXFR     bool `json:"allow_axfr"`
}

// ScopeExporter writes signed network-authorization files for the kali-runner.
// It is deliberately server-owned: db must not depend on the data directory.
type ScopeExporter struct {
	DB     *db.DB
	Dir    string
	Key    []byte
	TTL    time.Duration
	Policy ScopePolicy

	mu sync.Mutex
}

// NewScopeExporterFromEnv builds the exporter from ARTEX_SCOPE_* settings. It
// returns (nil, nil) when ARTEX_SCOPE_KEY is unset: the non-web runner profile
// is then disabled and no scope files are written.
func NewScopeExporterFromEnv(dataDir string, database *db.DB) (*ScopeExporter, error) {
	rawKey := strings.TrimSpace(os.Getenv("ARTEX_SCOPE_KEY"))
	if rawKey == "" {
		return nil, nil
	}
	key, err := decodeScopeKey(rawKey)
	if err != nil {
		return nil, err
	}
	dir := strings.TrimSpace(os.Getenv("ARTEX_SCOPE_DIR"))
	if dir == "" {
		dir = filepath.Join(dataDir, "scopes")
	}
	ttl := 720 * time.Hour
	if raw := strings.TrimSpace(os.Getenv("ARTEX_SCOPE_TTL")); raw != "" {
		ttl, err = time.ParseDuration(raw)
		if err != nil || ttl <= 0 {
			return nil, fmt.Errorf("ARTEX_SCOPE_TTL must be a positive duration")
		}
	}
	maxRate := 500
	if raw := strings.TrimSpace(os.Getenv("ARTEX_SCOPE_POLICY_MAX_RATE")); raw != "" {
		maxRate, err = strconv.Atoi(raw)
		if err != nil || maxRate < 1 || maxRate > 1000 {
			return nil, fmt.Errorf("ARTEX_SCOPE_POLICY_MAX_RATE must be between 1 and 1000")
		}
	}
	maxHosts := 4096
	if raw := strings.TrimSpace(os.Getenv("ARTEX_SCOPE_POLICY_MAX_HOSTS")); raw != "" {
		maxHosts, err = strconv.Atoi(raw)
		if err != nil || maxHosts < 1 || maxHosts > 65536 {
			return nil, fmt.Errorf("ARTEX_SCOPE_POLICY_MAX_HOSTS must be between 1 and 65536")
		}
	}
	policy := ScopePolicy{
		MaxRate:       maxRate,
		MaxHosts:      maxHosts,
		AllowSYN:      envBool("ARTEX_SCOPE_ALLOW_SYN"),
		AllowOSDetect: envBool("ARTEX_SCOPE_ALLOW_OS_DETECT"),
		AllowAXFR:     envBool("ARTEX_SCOPE_ALLOW_AXFR"),
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create scope dir %s: %w", dir, err)
	}
	return &ScopeExporter{DB: database, Dir: dir, Key: key, TTL: ttl, Policy: policy}, nil
}

func decodeScopeKey(raw string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		key, err = base64.RawStdEncoding.DecodeString(raw)
	}
	if err != nil {
		return nil, fmt.Errorf("ARTEX_SCOPE_KEY must be valid base64")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("ARTEX_SCOPE_KEY must decode to exactly 32 bytes")
	}
	return key, nil
}

// Sync writes (or preserves) the signed scope file for one task. It is
// best-effort for callers on the request path: authorization changes are also
// picked up by the 30-second reconciler.
func (e *ScopeExporter) Sync(taskID int64) error {
	if e == nil || e.DB == nil {
		return nil
	}
	if taskID <= 0 {
		return fmt.Errorf("task_id is required")
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	snap, err := e.DB.TaskScopeSnapshot(taskID)
	if err != nil {
		return err
	}
	exclusions, err := readScopeExclusions(filepath.Join(e.Dir, fmt.Sprintf("%d.exclude.json", taskID)))
	if err != nil {
		log.Printf("[scope] task %d: ignoring exclusions: %v", taskID, err)
		exclusions = scopeExclusions{}
	}
	now := time.Now().UTC().Truncate(time.Second)
	payload, err := e.buildPayload(snap, exclusions, now, now.Add(e.TTL))
	if err != nil {
		return err
	}
	path := filepath.Join(e.Dir, fmt.Sprintf("%d.json", taskID))
	if preserved, err := e.preserveExisting(path, payload, now); err != nil {
		return err
	} else if preserved {
		return nil
	}
	signature, err := signScopePayload(payload, e.Key)
	if err != nil {
		return err
	}
	payload["signature"] = signature
	return writeScopeFile(path, payload)
}

// ReconcileActive rewrites changed scope files for every non-archived,
// non-deleted task. Per-task failures are returned joined so the caller can log
// them without stopping the sweep.
func (e *ScopeExporter) ReconcileActive(ctx context.Context) error {
	if e == nil || e.DB == nil {
		return nil
	}
	rows, err := e.DB.Query(`SELECT id FROM tasks WHERE deleted_at IS NULL AND archived_at IS NULL ORDER BY id`)
	if err != nil {
		return err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}

	var errs []error
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		if err := e.Sync(id); err != nil {
			errs = append(errs, fmt.Errorf("task %d: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

func (e *ScopeExporter) buildPayload(snap db.ScopeSnapshot, excl scopeExclusions, issued, expires time.Time) (map[string]any, error) {
	nonce, err := scopeNonce()
	if err != nil {
		return nil, err
	}
	excl.Domains = normalizeExcludeDomains(excl.Domains)
	excl.IPs = normalizeExcludeIPs(excl.IPs)
	excl.CIDRs = normalizeExcludeCIDRs(excl.CIDRs)
	excl.Ports = normalizeExcludePorts(excl.Ports)
	domains, ips, cidrs, ports := mergeScopeExclusions(snap.Domains, snap.IPs, snap.CIDRs, nil, excl)
	excludes := make([]string, 0, len(excl.Domains)+len(excl.IPs)+len(excl.CIDRs))
	excludes = append(excludes, excl.Domains...)
	excludes = append(excludes, excl.IPs...)
	excludes = append(excludes, excl.CIDRs...)
	sort.Strings(excludes)
	payload := map[string]any{
		"schema":        scopeSchema,
		"task_id":       snap.TaskID,
		"company_id":    snap.CompanyID,
		"engagement":    fmt.Sprintf("task-%d", snap.TaskID),
		"domains":       nonNilStrings(domains),
		"ips":           nonNilStrings(ips),
		"cidrs":         nonNilStrings(cidrs),
		"excludes":      nonNilStrings(excludes),
		"exclude_ports": nonNilInts(ports),
		"policy": map[string]any{
			"max_rate":        e.Policy.MaxRate,
			"max_hosts":       e.Policy.MaxHosts,
			"allow_syn":       e.Policy.AllowSYN,
			"allow_os_detect": e.Policy.AllowOSDetect,
			"allow_axfr":      e.Policy.AllowAXFR,
		},
		"issued_at":  issued.Format(time.RFC3339),
		"expires_at": expires.Format(time.RFC3339),
		"nonce":      nonce,
	}
	return payload, nil
}

// preserveExisting keeps a signed file when the authorization content is
// unchanged and the signature verifies. This avoids rewriting every task every
// 30 seconds (and keeps issued_at stable for operators diffing the directory).
func (e *ScopeExporter) preserveExisting(path string, payload map[string]any, now time.Time) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	var existing map[string]any
	if err := json.Unmarshal(raw, &existing); err != nil {
		return false, nil
	}
	if !verifyScopeSignature(existing, e.Key) {
		return false, nil
	}
	if !scopeExpiryComfortable(existing["expires_at"], now) {
		return false, nil
	}
	want, err := scopeAuthorizationFingerprint(payload)
	if err != nil {
		return false, err
	}
	got, err := scopeAuthorizationFingerprint(existing)
	if err != nil {
		return false, err
	}
	return bytes.Equal(want, got), nil
}

func scopeExpiryComfortable(raw any, now time.Time) bool {
	text, ok := raw.(string)
	if !ok {
		return false
	}
	expires, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return false
	}
	return expires.Sub(now) > scopeRefreshWindow
}

// scopeAuthorizationFingerprint strips the volatile fields and canonicalizes
// the rest. Two payloads with the same fingerprint authorize the same targets.
func scopeAuthorizationFingerprint(payload map[string]any) ([]byte, error) {
	body := make(map[string]any, len(payload))
	for k, v := range payload {
		switch k {
		case "issued_at", "expires_at", "nonce", "signature":
			continue
		}
		body[k] = v
	}
	return canonicalScopeJSON(body)
}

// canonicalScopeJSON matches the runner's canonicalization exactly:
// sorted keys, no whitespace, UTF-8, no HTML escaping.
func canonicalScopeJSON(payload map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func signScopePayload(payload map[string]any, key []byte) (string, error) {
	body := make(map[string]any, len(payload))
	for k, v := range payload {
		if k == "signature" {
			continue
		}
		body[k] = v
	}
	canonical, err := canonicalScopeJSON(body)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(canonical)
	return scopeSignaturePref + hex.EncodeToString(mac.Sum(nil)), nil
}

func verifyScopeSignature(payload map[string]any, key []byte) bool {
	raw, ok := payload["signature"].(string)
	if !ok || !strings.HasPrefix(raw, scopeSignaturePref) {
		return false
	}
	provided := strings.TrimPrefix(raw, scopeSignaturePref)
	if len(provided) != 64 {
		return false
	}
	want, err := signScopePayload(payload, key)
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(provided), []byte(strings.TrimPrefix(want, scopeSignaturePref)))
}

func scopeNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func writeScopeFile(path string, payload map[string]any) error {
	body, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	// Best-effort directory fsync; not available on every platform.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

type scopeExclusions struct {
	Domains []string `json:"domains"`
	IPs     []string `json:"ips"`
	CIDRs   []string `json:"cidrs"`
	Ports   []int    `json:"ports"`
}

func readScopeExclusions(path string) (scopeExclusions, error) {
	var out scopeExclusions
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, err
	}
	if fi.Size() > scopeMaxExclude {
		return out, fmt.Errorf("exclusion file exceeds %d bytes", scopeMaxExclude)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return scopeExclusions{}, err
	}
	out.Domains = normalizeExcludeDomains(out.Domains)
	out.IPs = normalizeExcludeIPs(out.IPs)
	out.CIDRs = normalizeExcludeCIDRs(out.CIDRs)
	out.Ports = normalizeExcludePorts(out.Ports)
	return out, nil
}

func normalizeExcludeDomains(in []string) []string {
	seen := map[string]struct{}{}
	for _, raw := range in {
		d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if d == "" {
			continue
		}
		seen[d] = struct{}{}
	}
	return sortedStringSet(seen)
}

func normalizeExcludeIPs(in []string) []string {
	seen := map[string]struct{}{}
	for _, raw := range in {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil {
			log.Printf("[scope] ignoring invalid exclusion IP %q", raw)
			continue
		}
		seen[ip.String()] = struct{}{}
	}
	return sortedStringSet(seen)
}

func normalizeExcludeCIDRs(in []string) []string {
	seen := map[string]struct{}{}
	for _, raw := range in {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			log.Printf("[scope] ignoring invalid exclusion network %q", raw)
			continue
		}
		seen[ipnet.String()] = struct{}{}
	}
	return sortedStringSet(seen)
}

func normalizeExcludePorts(in []int) []int {
	seen := map[int]struct{}{}
	for _, port := range in {
		if port < 1 || port > 65535 {
			log.Printf("[scope] ignoring invalid exclusion port %d", port)
			continue
		}
		seen[port] = struct{}{}
	}
	out := make([]int, 0, len(seen))
	for port := range seen {
		out = append(out, port)
	}
	sort.Ints(out)
	return out
}

// mergeScopeExclusions returns deduplicated, sorted authorization lists plus
// the merged exclude-port list. Exclusions are emitted separately by the
// caller; this function only normalizes the signed fields.
func mergeScopeExclusions(domains, ips, cidrs []string, ports []int, excl scopeExclusions) ([]string, []string, []string, []int) {
	dset := map[string]struct{}{}
	for _, d := range domains {
		if v := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), "."); v != "" {
			dset[v] = struct{}{}
		}
	}
	iset := map[string]struct{}{}
	for _, raw := range ips {
		if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil {
			iset[ip.String()] = struct{}{}
		}
	}
	cset := map[string]struct{}{}
	for _, raw := range cidrs {
		if _, ipnet, err := net.ParseCIDR(strings.TrimSpace(raw)); err == nil {
			cset[ipnet.String()] = struct{}{}
		}
	}
	pset := map[int]struct{}{}
	for _, p := range ports {
		if p >= 1 && p <= 65535 {
			pset[p] = struct{}{}
		}
	}
	for _, p := range excl.Ports {
		pset[p] = struct{}{}
	}
	portsOut := make([]int, 0, len(pset))
	for p := range pset {
		portsOut = append(portsOut, p)
	}
	sort.Ints(portsOut)
	return sortedStringSet(dset), sortedStringSet(iset), sortedStringSet(cset), portsOut
}

func sortedStringSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func nonNilInts(in []int) []int {
	if in == nil {
		return []int{}
	}
	return in
}

// syncTaskScope is the server-side best-effort hook used by request handlers
// and task lifecycle paths.
func (s *Server) syncTaskScope(taskID int64) {
	if s == nil || s.scope == nil {
		return
	}
	if err := s.scope.Sync(taskID); err != nil {
		log.Printf("[scope] task %d: sync failed: %v", taskID, err)
	}
}

// runScopeReconciler performs an immediate sweep, then every 30 seconds. The
// interactive API paths sync immediately; this covers planner/auto scope
// changes and operator exclusion-file edits.
func (s *Server) runScopeReconciler(ctx context.Context) {
	if s == nil || s.scope == nil {
		return
	}
	sweep := func() {
		if err := s.scope.ReconcileActive(ctx); err != nil {
			log.Printf("[scope] reconcile: %v", err)
		}
	}
	sweep()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep()
		}
	}
}
