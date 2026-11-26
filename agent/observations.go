package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

const (
	runnerToolPrefix       = "mcp__kali_runner__"
	runnerEnvelopeSchema   = "artex.runner.v1"
	runnerResultSchema     = "artex.runner.result.v1"
	maxRunnerObservations  = 50000
	maxRunnerResultBytes   = 64 * 1024 * 1024
	maxRunnerHostnames     = 100
	maxRunnerInlinePreview = 200
)

// ObservationIngestor turns a kali-runner envelope into asset rows. It is
// deliberately best-effort: a parse/write failure is logged and never blocks
// the tool call or the agent. It never widens task scope.
type ObservationIngestor struct {
	Assets  *db.AssetStore
	DataDir string
	TaskID  int64
}

type runnerArtifactRef struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type runnerEnvelope struct {
	Schema            string              `json:"schema"`
	OK                bool                `json:"ok"`
	JobID             string              `json:"job_id"`
	TaskID            int64               `json:"task_id"`
	Tool              string              `json:"tool"`
	State             string              `json:"state"`
	ResultArtifact    *runnerArtifactRef  `json:"result_artifact"`
	Observations      []runnerObservation `json:"observations"`
	ObservationsTotal int                 `json:"observations_total"`
	Truncated         bool                `json:"truncated"`
	Error             map[string]any      `json:"error"`
}

type runnerResult struct {
	Schema       string              `json:"schema"`
	OK           bool                `json:"ok"`
	JobID        string              `json:"job_id"`
	TaskID       int64               `json:"task_id"`
	Tool         string              `json:"tool"`
	State        string              `json:"state"`
	Observations []runnerObservation `json:"observations"`
}

type runnerObservation struct {
	Kind      string         `json:"kind"`
	IP        string         `json:"ip"`
	Domain    string         `json:"domain"`
	Hostnames []string       `json:"hostnames"`
	Port      int            `json:"port"`
	Proto     string         `json:"proto"`
	Service   string         `json:"service"`
	Product   string         `json:"product"`
	Version   string         `json:"version"`
	ExtraInfo string         `json:"extrainfo"`
	Tunnel    string         `json:"tunnel"`
	Method    string         `json:"method"`
	Extra     map[string]any `json:"extra"`
}

// WithObservationIngestion wraps a hook runner so runner results are ingested
// before the inner PostToolUse (guard) logic runs. PreToolUse/Stop delegate
// unchanged.
func WithObservationIngestion(inner harness.HookRunner, as *db.AssetStore, dataDir string, taskID int64) harness.HookRunner {
	if as == nil || taskID <= 0 || strings.TrimSpace(dataDir) == "" {
		return inner
	}
	return observationHooks{
		inner: inner,
		ing: ObservationIngestor{
			Assets:  as,
			DataDir: dataDir,
			TaskID:  taskID,
		},
	}
}

type observationHooks struct {
	inner harness.HookRunner
	ing   ObservationIngestor
}

func (h observationHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	if h.inner == nil {
		return false, "", nil
	}
	return h.inner.PreToolUse(ctx, name, input)
}

func (h observationHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	if !isErr && strings.HasPrefix(name, runnerToolPrefix) {
		if err := h.ing.Ingest(name, result); err != nil {
			log.Printf("[runner] task %d: observation ingestion failed for %s: %v", h.ing.TaskID, name, err)
		}
	}
	if h.inner != nil {
		h.inner.PostToolUse(ctx, name, input, result, isErr)
	}
}

func (h observationHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	if h.inner == nil {
		return false, nil, ""
	}
	return h.inner.Stop(ctx, messages)
}

// Ingest parses one tool result and persists ip/service observations. The
// result may be a JSON string (the harness marshals tool text) and may be
// truncated by the global output cap; the result_artifact reference is placed
// early enough that it survives truncation.
func (i ObservationIngestor) Ingest(toolName string, raw []byte) error {
	if i.Assets == nil || i.TaskID <= 0 {
		return nil
	}
	text := decodeRunnerToolText(raw)
	env, inline, err := parseRunnerEnvelope(text)
	if err != nil {
		return err
	}
	if env == nil {
		return fmt.Errorf("not a runner envelope")
	}
	if env.Schema != runnerEnvelopeSchema {
		return fmt.Errorf("unexpected envelope schema %q", env.Schema)
	}
	if !env.OK {
		return nil
	}
	if env.TaskID != i.TaskID {
		return fmt.Errorf("envelope task_id=%d, current task=%d", env.TaskID, i.TaskID)
	}

	observations := inline
	if env.ResultArtifact != nil {
		res, err := i.readResultArtifact(env)
		if err != nil {
			log.Printf("[runner] task %d: result artifact unusable, falling back to inline observations: %v", i.TaskID, err)
		} else {
			observations = res.Observations
		}
	}
	if len(observations) == 0 {
		return nil
	}
	if len(observations) > maxRunnerObservations {
		log.Printf("[runner] task %d: observation cap reached (%d > %d), stopping", i.TaskID, len(observations), maxRunnerObservations)
		observations = observations[:maxRunnerObservations]
	}
	return i.persist(observations)
}

func decodeRunnerToolText(raw []byte) []byte {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	var text string
	if err := json.Unmarshal(trimmed, &text); err == nil {
		return []byte(text)
	}
	return trimmed
}

func parseRunnerEnvelope(text []byte) (*runnerEnvelope, []runnerObservation, error) {
	if len(bytes.TrimSpace(text)) == 0 {
		return nil, nil, fmt.Errorf("empty tool result")
	}
	var env runnerEnvelope
	if err := json.Unmarshal(text, &env); err == nil {
		return &env, env.Observations, nil
	}

	// The global output cap may have cut the envelope mid-JSON. Extract the
	// early result_artifact object and any complete inline observations.
	env.Schema = extractRunnerString(text, "schema")
	env.JobID = extractRunnerString(text, "job_id")
	env.Tool = extractRunnerString(text, "tool")
	env.State = extractRunnerString(text, "state")
	env.OK = extractRunnerBool(text, "ok")
	env.TaskID = extractRunnerInt(text, "task_id")
	if obj := extractRunnerObject(text, "result_artifact"); obj != nil {
		var ref runnerArtifactRef
		if err := json.Unmarshal(obj, &ref); err == nil && ref.Path != "" {
			env.ResultArtifact = &ref
		}
	}
	inline := extractRunnerObservations(text)
	if env.Schema == "" && env.ResultArtifact == nil && len(inline) == 0 {
		return nil, nil, fmt.Errorf("tool result is not a runner envelope")
	}
	return &env, inline, nil
}

func (i ObservationIngestor) readResultArtifact(env *runnerEnvelope) (*runnerResult, error) {
	ref := env.ResultArtifact
	if ref == nil || strings.TrimSpace(ref.Path) == "" {
		return nil, fmt.Errorf("result_artifact.path is empty")
	}
	rel := filepath.ToSlash(strings.TrimSpace(ref.Path))
	if filepath.IsAbs(ref.Path) || strings.HasPrefix(rel, "/") {
		return nil, fmt.Errorf("result artifact path is absolute")
	}
	for _, part := range strings.Split(rel, "/") {
		if part == ".." || part == "" {
			return nil, fmt.Errorf("result artifact path is not a clean relative path")
		}
	}
	prefix := fmt.Sprintf("%d/runner/", i.TaskID)
	if !strings.HasPrefix(rel, prefix) {
		return nil, fmt.Errorf("result artifact path %q is outside task %d", rel, i.TaskID)
	}
	base := filepath.Join(i.DataDir, "tasks")
	full := filepath.Join(base, filepath.FromSlash(rel))
	if inside, err := filepath.Rel(base, full); err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("result artifact path escapes the task directory")
	}
	fi, err := os.Stat(full)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("result artifact is a directory")
	}
	if fi.Size() > maxRunnerResultBytes {
		return nil, fmt.Errorf("result artifact is too large (%d bytes)", fi.Size())
	}
	if ref.Bytes > 0 && fi.Size() != ref.Bytes {
		return nil, fmt.Errorf("result artifact size=%d, expected %d", fi.Size(), ref.Bytes)
	}
	raw, err := os.ReadFile(full)
	if err != nil {
		return nil, err
	}
	if ref.SHA256 != "" {
		sum := sha256.Sum256(raw)
		got := hex.EncodeToString(sum[:])
		if !strings.EqualFold(got, strings.TrimSpace(ref.SHA256)) {
			return nil, fmt.Errorf("result artifact sha256 mismatch")
		}
	}
	var res runnerResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("parse result.json: %w", err)
	}
	if res.Schema != runnerResultSchema {
		return nil, fmt.Errorf("unexpected result schema %q", res.Schema)
	}
	if res.TaskID != i.TaskID {
		return nil, fmt.Errorf("result task_id=%d, current task=%d", res.TaskID, i.TaskID)
	}
	if env.JobID != "" && res.JobID != "" && env.JobID != res.JobID {
		return nil, fmt.Errorf("result job_id=%s, envelope job_id=%s", res.JobID, env.JobID)
	}
	return &res, nil
}

func (i ObservationIngestor) persist(observations []runnerObservation) error {
	portsByIP := map[string]map[int]string{}
	for _, obs := range observations {
		if strings.ToLower(strings.TrimSpace(obs.Kind)) != "service" {
			continue
		}
		ip := strings.TrimSpace(obs.IP)
		if ip == "" || obs.Port <= 0 {
			continue
		}
		ports := portsByIP[ip]
		if ports == nil {
			ports = map[int]string{}
			portsByIP[ip] = ports
		}
		name := strings.ToLower(strings.TrimSpace(obs.Service))
		if name == "" {
			name = "unknown"
		}
		if existing, ok := ports[obs.Port]; !ok || existing == "unknown" || existing == "" {
			ports[obs.Port] = name
		}
	}

	seenIP := map[string]bool{}
	seenService := map[string]bool{}
	for _, obs := range observations {
		switch strings.ToLower(strings.TrimSpace(obs.Kind)) {
		case "ip":
			ip := strings.TrimSpace(obs.IP)
			if ip == "" || seenIP[ip] {
				continue
			}
			seenIP[ip] = true
			ports := make([]db.PortService, 0, len(portsByIP[ip]))
			for port, name := range portsByIP[ip] {
				ports = append(ports, db.PortService{Port: port, Service: name})
			}
			sort.Slice(ports, func(a, b int) bool { return ports[a].Port < ports[b].Port })
			if _, err := i.Assets.UpsertIP(db.UpsertIPReq{
				IP:           ip,
				BoundDomains: boundedHostnames(obs.Hostnames),
				OpenPorts:    ports,
				TaskID:       i.TaskID,
			}); err != nil {
				log.Printf("[runner] task %d: upsert ip %s: %v", i.TaskID, ip, err)
			}
		case "service":
			ip := strings.TrimSpace(obs.IP)
			domain := strings.TrimSpace(obs.Domain)
			name := strings.ToLower(strings.TrimSpace(obs.Service))
			if (ip == "" && domain == "") || obs.Port <= 0 || name == "" {
				continue
			}
			key := fmt.Sprintf("%s|%s|%d|%s", ip, domain, obs.Port, name)
			if seenService[key] {
				continue
			}
			seenService[key] = true
			req := db.UpsertOtherServiceReq{
				IP:          ip,
				Domain:      domain,
				Port:        obs.Port,
				ServiceName: name,
				TaskID:      i.TaskID,
			}
			if extra := observationExtra(obs); len(extra) > 0 {
				req.Extra = extra
			}
			if _, err := i.Assets.UpsertOtherService(req); err != nil {
				log.Printf("[runner] task %d: upsert service %s:%d/%s: %v", i.TaskID, ip, obs.Port, name, err)
			}
		}
	}
	return nil
}

func observationExtra(obs runnerObservation) map[string]any {
	extra := map[string]any{}
	for k, v := range obs.Extra {
		extra[k] = v
	}
	for key, value := range map[string]string{
		"product":   obs.Product,
		"version":   obs.Version,
		"extrainfo": obs.ExtraInfo,
		"tunnel":    obs.Tunnel,
		"method":    obs.Method,
		"proto":     obs.Proto,
	} {
		if strings.TrimSpace(value) != "" {
			extra[key] = strings.TrimSpace(value)
		}
	}
	return extra
}

func boundedHostnames(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, raw := range in {
		h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if h == "" || len(h) > 253 || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
		if len(out) >= maxRunnerHostnames {
			break
		}
	}
	return out
}

// extractRunnerString finds a top-level-ish string value after a key. It is a
// fallback for a truncated envelope, not a general JSON parser.
func extractRunnerString(text []byte, key string) string {
	idx := bytes.Index(text, []byte(`"`+key+`"`))
	if idx < 0 {
		return ""
	}
	i := idx + len(key) + 2
	for i < len(text) && (text[i] == ' ' || text[i] == '\t' || text[i] == '\n' || text[i] == '\r' || text[i] == ':') {
		i++
	}
	if i >= len(text) || text[i] != '"' {
		return ""
	}
	start := i
	i++
	escaped := false
	for ; i < len(text); i++ {
		if escaped {
			escaped = false
			continue
		}
		if text[i] == '\\' {
			escaped = true
			continue
		}
		if text[i] == '"' {
			var out string
			if json.Unmarshal(text[start:i+1], &out) == nil {
				return out
			}
			return ""
		}
	}
	return ""
}

func extractRunnerInt(text []byte, key string) int64 {
	idx := bytes.Index(text, []byte(`"`+key+`"`))
	if idx < 0 {
		return 0
	}
	i := idx + len(key) + 2
	for i < len(text) && (text[i] == ' ' || text[i] == '\t' || text[i] == '\n' || text[i] == '\r' || text[i] == ':') {
		i++
	}
	start := i
	for i < len(text) && text[i] >= '0' && text[i] <= '9' {
		i++
	}
	if i == start {
		return 0
	}
	n, _ := strconv.ParseInt(string(text[start:i]), 10, 64)
	return n
}

func extractRunnerBool(text []byte, key string) bool {
	idx := bytes.Index(text, []byte(`"`+key+`"`))
	if idx < 0 {
		return false
	}
	i := idx + len(key) + 2
	for i < len(text) && (text[i] == ' ' || text[i] == '\t' || text[i] == '\n' || text[i] == '\r' || text[i] == ':') {
		i++
	}
	return i+4 <= len(text) && string(text[i:i+4]) == "true"
}

// extractRunnerObject returns the balanced JSON object after a key. Strings
// and escapes are tracked so braces inside observation text cannot fool it.
func extractRunnerObject(text []byte, key string) []byte {
	idx := bytes.Index(text, []byte(`"`+key+`"`))
	if idx < 0 {
		return nil
	}
	i := idx + len(key) + 2
	for i < len(text) && (text[i] == ' ' || text[i] == '\t' || text[i] == '\n' || text[i] == '\r' || text[i] == ':') {
		i++
	}
	if i >= len(text) || text[i] != '{' {
		return nil
	}
	start := i
	depth := 0
	inString := false
	escaped := false
	for ; i < len(text); i++ {
		c := text[i]
		if inString {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return text[start : i+1]
			}
		}
	}
	return nil
}

// extractRunnerObservations decodes complete array elements from a possibly
// truncated observations array.
func extractRunnerObservations(text []byte) []runnerObservation {
	idx := bytes.Index(text, []byte(`"observations"`))
	if idx < 0 {
		return nil
	}
	i := idx + len(`"observations"`)
	for i < len(text) && (text[i] == ' ' || text[i] == '\t' || text[i] == '\n' || text[i] == '\r' || text[i] == ':') {
		i++
	}
	if i >= len(text) || text[i] != '[' {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(text[i:]))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('[') {
		return nil
	}
	out := []runnerObservation{}
	for dec.More() && len(out) < maxRunnerInlinePreview {
		var obs runnerObservation
		if err := dec.Decode(&obs); err != nil {
			break
		}
		out = append(out, obs)
	}
	return out
}
